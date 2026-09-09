# PLIŌRA Threat Monitor — Partner & Reseller Billing Models Architecture

**Specification Reference:** Roadmap §D.2 (§5: Partner/Reseller Billing Considerations)  
**Status:** Architectural Decision & Design Document for Future Billing Expansion Spec

---

## 1. Current Baseline Invariant: Billing Neutrality

Under the current architecture established in Roadmap §D.2:
- **Zero Billing Mutation**: Establishing, accepting, delegating branding for, or revoking an `AgencyClientLink` has **strictly zero effect** on either organization's Stripe subscription state or billing lifecycle.
- **Direct Relationships**: The client organization maintains its direct billing contract with PLIŌRA via Stripe (handling its own `stripeCustomerId`, `stripeSubscriptionId`, tier quotas, and payment methods).
- **Decoupled Access**: The agency organization accesses the client account strictly as an authorized external security operator with read-only scopes. No seat fees, transfer charges, or invoice line items are triggered.

This invariant guarantees that agency partnership features can be rolled out safely without risk of accidental double-billing, invoice errors, or orphan subscription states.

---

## 2. Evaluation of Future Reseller Billing Models

When PLIŌRA expands partner monetization beyond direct client subscriptions, two distinct models are viable. Below is a comparative architectural evaluation:

```
+-----------------------------------------------------------------------------------------------+
|                                  MODEL 1: WHOLESALE PARTNER INVOICING                        |
|                                                                                               |
|   +--------------------+     Single Invoice (Volume Discount)     +-----------------------+   |
|   |  Agency / MSP Org  | <======================================> |  PLIŌRA Threat Monitor|   |
|   +--------------------+                                          +-----------------------+   |
|            |                                                                                  |
|            | Bills Client Privately (Bundled Managed Service)                                 |
|            v                                                                                  |
|   +--------------------+                                                                      |
|   |  Client Org A, B, C|                                                                      |
|   +--------------------+                                                                      |
+-----------------------------------------------------------------------------------------------+

+-----------------------------------------------------------------------------------------------+
|                               MODEL 2: DIRECT CLIENT BILLING + PARTNER REBATE                 |
|                                                                                               |
|   +--------------------+               Direct Stripe Subscription +-----------------------+   |
|   |  Client Org A, B, C| <======================================> |  PLIŌRA Threat Monitor|   |
|   +--------------------+                                          +-----------------------+   |
|                                                                               |               |
|                                           Monthly Revenue Share / Rebate (20%)|               |
|                                                                               v               |
|                                                                   +-----------------------+   |
|                                                                   |    Agency / MSP Org   |   |
|                                                                   +-----------------------+   |
+-----------------------------------------------------------------------------------------------+
```

---

### Model 1: Wholesale Partner Seat Invoicing (Agency-Managed Billing)

In this model, the MSP/Agency purchases a pool of client organization slots (e.g., 10, 25, or 100 monitored organizations) from PLIŌRA at a tiered wholesale discount (e.g., 30–40% off list price). The agency bundles PLIŌRA's threat monitoring into its own managed security retainer and invoices the end client directly.

#### Architectural Mechanics:
1. **Agency Stripe Subscription**: The agency's `stripeSubscriptionId` contains metered or tiered seat items (`price_agency_seat_tier1`).
2. **Client Provisioning**: The agency can provision a new client organization directly from its dashboard, immediately claiming an allocation from its quota pool.
3. **Client Billing Bypass**: The client organization's `subscriptionStatus` is marked `MANAGED_BY_AGENCY`, bypassing the standard self-serve Stripe checkout modal while inheriting the feature entitlements (e.g., PRO scan quotas, white-label PDF reports) contracted by the agency.
4. **Delinquency Cascade**: If the agency's payment method fails, a grace period notification is dispatched to the agency administrator. If canceled, all managed client organizations transition to restricted read-only mode after a 14-day compliance hold.

#### Strengths:
- **Low Friction for Clients**: Client organizations never need to enter credit card details into PLIŌRA; the agency handles procurement.
- **High Retention & Large Deal Size**: MSPs commit to annual wholesale commitments, creating predictable ARR with lower customer acquisition costs.
- **White-Label Purity**: The client may never know PLIŌRA's retail pricing, allowing the agency to charge a markup that includes human remediation services.

#### Trade-offs & Risks:
- **Concentration Risk**: If an agency churns, multiple client accounts churn simultaneously.
- **Offboarding Friction**: If a client terminates its agency relationship, transferring the monitored domain history to a direct client subscription requires account ownership re-parenting.

---

### Model 2: Client Direct Subscription with Partner Revenue Share (Affiliate / Co-Sell)

In this model, each client organization enters its own credit card and subscribes to PLIŌRA directly. The agency is registered as the "Certified Security Partner" on the account. PLIŌRA tracks attribution and pays the agency an automated recurring revenue share (e.g., 20% of MRR) via Stripe Connect.

#### Architectural Mechanics:
1. **Direct Stripe Customer**: Each client organization retains an independent `stripeCustomerId` and standard self-serve plan tier.
2. **Attribution Linking**: The `AgencyClientLink` records the partner attribution code.
3. **Stripe Connect Payouts**: When the client's monthly subscription charge succeeds, a Stripe webhook (`invoice.payment_succeeded`) calculates the partner cut and triggers a Stripe Transfer (`stripe.transfers.create`) to the agency's connected account.
4. **Revocation Independence**: If the client revokes the agency link, the client's subscription remains uninterrupted and active without disruption to security scanning or data retention.

#### Strengths:
- **Zero Credit Risk for PLIŌRA**: No exposure to agency insolvency or delayed accounts payable.
- **Zero Offboarding Complexity**: When a client parts ways with an agency, the client simply clicks "Revoke Access" in settings; monitoring and billing continue seamlessly.
- **Compliance Simplicity**: Avoids reselling tax/VAT complications in multi-jurisdictional partner networks.

#### Trade-offs & Risks:
- **Agency Resistance**: High-end MSPs prefer unified customer billing and dislike exposing vendor SaaS costs to their clients.
- **Stripe Connect Overhead**: Requires KYC/AML onboarding for partner payout accounts.

---

## 3. Recommended Phasing & Roadmap Recommendation

| Phase | Model | Scope & Trigger |
|---|---|---|
| **Current (Roadmap D.2)** | **Billing Neutrality** | Zero Stripe mutation. Access and reporting are decoupled from billing. Fully audited. |
| **Expansion Phase 1** | **Hybrid Direct + Partner Co-Sell (Model 2)** | Client direct billing with manual or Stripe Connect referral credits. Ideal for agency consultants recommending PLIŌRA. |
| **Expansion Phase 2** | **Full Wholesale MSP Billing (Model 1)** | Dedicated MSP multi-seat plans with agency-level Stripe subscriptions and client seat allocations. |

---

## 4. Key Security Invariants for Any Future Reseller Billing Implementation

1. **Isolation from Payment Secrets**: Client organizations must never have visibility into agency payment methods or billing invoices.
2. **Non-Destructive Termination**: If an agency link is revoked, client historical finding evidence, scan history, and domain assets must NEVER be deleted.
3. **Explicit Consent on Managed Billing**: Converting an independently paying client to an agency-billed plan must require cryptographic confirmation from the client organization's `OWNER`.
