# PLIŌRA Threat Monitor — Customer API & Webhooks Reference

Welcome to the **PLIŌRA Threat Monitor API Reference**. This guide describes how to authenticate, query real-time threat intelligence and security findings, configure outbound webhook alerts, and verify cryptographic webhook payloads.

---

## 1. Authentication

The customer-facing API is rooted at `/api/v1/*`. All endpoints require authentication via an API Key generated in your organization settings.

### Request Header
```http
Authorization: Bearer plk_live_xxxxxxxxxxxxxxxxxxxxxxxx
```

- Keys use the prefix `plk_live_` or `plk_test_`.
- API keys are hashed with **SHA-256** at rest. Only the masked prefix/suffix is retained for display in the dashboard.
- If the key is invalid, revoked, or expired, the API returns `401 Unauthorized`.

---

## 2. Rate Limits & Headers

Every API key has an independent rate limit of **60 requests per minute** computed on a rolling 60-second window.

### Response Headers
Every `/api/v1/*` response includes the following rate limit headers:
| Header | Description |
|---|---|
| `X-RateLimit-Limit` | Maximum requests permitted per window (default: `60`) |
| `X-RateLimit-Remaining` | Remaining calls available in the current window |
| `X-RateLimit-Reset` | Time in seconds until the current window quota resets |

### Exceeding the Rate Limit
When the limit is reached, the API immediately responds with **HTTP 429 Too Many Requests**:
```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
Retry-After: 42
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 42

{
  "success": false,
  "data": null,
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit of 60 requests per minute exceeded. Retry in 42 seconds."
  }
}
```

---

## 3. Standard Response Envelope

All `/api/v1/*` endpoints follow a strict, consistent JSON response envelope:

### Successful List Response
```json
{
  "success": true,
  "data": [ ... ],
  "meta": {
    "total": 45,
    "page": 1,
    "limit": 20,
    "totalPages": 3
  },
  "error": null
}
```

### Successful Object Response
```json
{
  "success": true,
  "data": { ... },
  "error": null
}
```

### Error Response
```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "UNAUTHORIZED",
    "message": "Invalid or missing Bearer token in Authorization header."
  }
}
```

---

## 4. Endpoints Reference

### 4.1 Findings (`GET /api/v1/findings`)
Retrieve active and historical security findings scoped to your organization.

#### Query Parameters:
| Parameter | Type | Description |
|---|---|---|
| `severity` | string | Filter by severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL` |
| `confidence` | string | Filter by confidence: `CONFIRMED`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL` |
| `status` | string | Filter by lifecycle: `OPEN`, `ACCEPTED_RISK`, `RESOLVED`, `FALSE_POSITIVE` |
| `category` | string | Filter by category (e.g. `TLS`, `DNS`, `SUBDOMAIN_TAKEOVER`, `DATABASE_MISCONFIG`, `CREDENTIAL_EXPOSURE`) |
| `assetId` | string | Filter findings for a specific monitored asset ID |
| `sortBy` | string | Sort field: `severity` (default), `riskScore`, `firstSeenAt`, `createdAt` |
| `sortOrder` | string | `asc` or `desc` (default: `desc`) |
| `page` | integer | Page index (default: `1`) |
| `limit` | integer | Results per page (default: `20`, maximum: `100`) |

---

### 4.2 Threats (`GET /api/v1/threats`)
Retrieve typosquats, impersonation domains, and external indicators detected for your registered roots.

#### Query Parameters:
| Parameter | Type | Description |
|---|---|---|
| `status` | string | `OPEN`, `MONITORING`, `ACCEPTED_RISK`, `RESOLVED` |
| `confidence` | string | `CONFIRMED`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL` |
| `source` | string | `CT_LOG`, `TYPOSQUAT_PERMUTATION`, `KEYWORD_MATCH`, `MANUAL_REPORT` |
| `relatedRootDomain` | string | Filter by monitored root domain (e.g., `example.com`) |
| `search` | string | Fuzzy substring search on indicator/domain name |
| `sortBy` | string | `corroborationScore` (default), `lastSeen`, `indicator`, `createdAt` |
| `sortOrder` | string | `asc` or `desc` (default: `desc`) |
| `page` | integer | Page index (default: `1`) |
| `limit` | integer | Results per page (default: `20`, maximum: `100`) |

---

### 4.3 Monitored Assets (`GET /api/v1/assets`)
List all attack surface assets registered and monitored under your organization.

#### Query Parameters:
| Parameter | Type | Description |
|---|---|---|
| `type` | string | `ROOT_DOMAIN`, `SUBDOMAIN`, `IP_ADDRESS`, `SERVICE` |
| `status` | string | Verification status: `VERIFIED`, `PENDING`, `FAILED`, `INHERITED_VERIFIED` |
| `rootDomain` | string | Monitored root domain filter |
| `importance` | string | `CRITICAL`, `HIGH`, `NORMAL`, `LOW` |
| `search` | string | Filter FQDN by substring |
| `sortBy` | string | `importance`, `fqdn`, `createdAt`, `lastSeen` |
| `sortOrder` | string | `asc` or `desc` (default: `desc`) |
| `page` | integer | Page index (default: `1`) |
| `limit` | integer | Results per page (default: `20`, maximum: `100`) |

---

### 4.4 Risk Score (`GET /api/v1/risk-score`)
Retrieve the live aggregate risk posture, letter grade, and breakdown for your organization.

#### Response Body:
```json
{
  "success": true,
  "data": {
    "score": 42,
    "securityPosture": 58,
    "grade": "C",
    "factors": {
      "criticalCount": 1,
      "highCount": 2,
      "mediumCount": 3,
      "lowCount": 0,
      "informationalCount": 1,
      "totalActiveFindings": 6,
      "acceptedRiskCount": 0,
      "topFindingScore": 65
    },
    "findingCounts": {
      "open": 6,
      "acceptedRisk": 0,
      "resolved": 12,
      "falsePositive": 1,
      "total": 19
    },
    "explanation": "Risk score 42/100 anchored by top finding (65 pts) with 6 active findings contributing. Grade: C."
  },
  "error": null
}
```

---

## 5. Webhooks & Alert Notifications

PLIŌRA allows organizations to deliver real-time security alerts directly to external HTTP endpoints or Slack channels.

### 5.1 Webhook Management (`/api/org/webhooks`)
- **GET `/api/org/webhooks`**: Lists configured webhook endpoints for the authenticated organization. Secrets are masked (`whsec_live_...****`).
- **POST `/api/org/webhooks`**: Registers a new webhook. The plaintext secret (`whsec_live_...`) is returned **only once** upon creation.
- **PATCH `/api/org/webhooks/:id`**: Update webhook URL, enabled alert types, or active status.
- **DELETE `/api/org/webhooks/:id`**: Remove an endpoint.

### 5.2 SSRF Protection Guard
All webhook URLs undergo mandatory validation prior to creation or update. The URL's target hostname is resolved using DNS:
- Requests targeting loopback addresses (`127.0.0.0/8`, `::1`), link-local metadata addresses (`169.254.169.254`), or private RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) are **strictly rejected** with `400 Bad Request` and error code `SSRF_VALIDATION_FAILED`.
- Non-HTTP/HTTPS schemes are blocked.

### 5.3 Webhook Formats
1. **`JSON` (Default)**: Sends a standardized JSON alert envelope.
2. **`SLACK`**: Sends a Slack Block Kit payload with color-coded attachments matching severity (`#dc2626` Critical, `#f97316` High, `#eab308` Medium, `#3b82f6` Low).

---

## 6. Webhook Payload & Signature Verification

### 6.1 Signature Header
Every outbound webhook includes the `X-Pliora-Signature` header:
```http
X-Pliora-Signature: t=1725619200,v1=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

- `t`: The UNIX timestamp (seconds) when the payload was dispatched.
- `v1`: The hexadecimal HMAC-SHA256 signature calculated over the string:
  ```
  ${t}.${rawBody}
  ```
  using your webhook secret (`whsec_live_...`).

---

### 6.2 Verification Code Snippet (Node.js / TypeScript)

```typescript
import crypto from 'crypto';

export function verifyPlioraSignature(
  rawBody: string,
  signatureHeader: string,
  webhookSecret: string,
  toleranceSeconds: number = 300
): boolean {
  // Parse t=... and v1=...
  const parts = signatureHeader.split(',');
  const timestampPart = parts.find((p) => p.startsWith('t='));
  const sigPart = parts.find((p) => p.startsWith('v1='));

  if (!timestampPart || !sigPart) {
    return false;
  }

  const timestamp = parseInt(timestampPart.substring(2), 10);
  const receivedSig = sigPart.substring(3);

  // Prevent replay attacks (within 5-minute tolerance)
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - timestamp) > toleranceSeconds) {
    return false; // Request too old or from the future
  }

  // Compute expected HMAC
  const signedPayload = `${timestamp}.${rawBody}`;
  const expectedSig = crypto
    .createHmac('sha256', webhookSecret)
    .update(signedPayload, 'utf8')
    .digest('hex');

  // Constant-time comparison
  const receivedBuf = Buffer.from(receivedSig, 'hex');
  const expectedBuf = Buffer.from(expectedSig, 'hex');

  if (receivedBuf.length !== expectedBuf.length) {
    return false;
  }

  return crypto.timingSafeEqual(receivedBuf, expectedBuf);
}
```

---

### 6.3 Example JSON Alert Payload
```json
{
  "event": "alert.triggered",
  "id": "alt-1725619200-abc",
  "organizationId": "66d3a1f8b4a2c10023456789",
  "alertType": "NEW_CRITICAL_FINDING",
  "severity": "CRITICAL",
  "title": "Critical Exposure Detected: Exposed Git Repository",
  "summary": "Publicly accessible .git/HEAD discovered on prod-app.example.com",
  "details": {
    "findingCode": "WEB-GIT-CONFIG-EXPOSED",
    "target": "https://prod-app.example.com/.git/HEAD",
    "confidence": "CONFIRMED",
    "riskScore": 95
  },
  "timestamp": "2026-09-06T12:00:00.000Z"
}
```
