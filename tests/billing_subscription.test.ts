import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { NextRequest } from 'next/server';
import { memoryStore } from '../src/lib/store';
import { POST as addAsset } from '../src/app/api/assets/route';
import { POST as createScan } from '../src/app/api/scans/route';
import { POST as checkout } from '../src/app/api/billing/checkout/route';
import { POST as portal } from '../src/app/api/billing/portal/route';
import { GET as getSubscription } from '../src/app/api/billing/subscription/route';
import { POST as billingWebhook } from '../src/app/api/billing/webhook/route';
import { PATCH as updateOrg } from '../src/app/api/org/route';
import { GET as exportReport } from '../src/app/api/reports/export/route';
import { createSessionToken } from '../src/lib/auth';
import { billingService } from '../src/lib/billing/stripe';
import { getPlanQuotas, getApiRateLimit, canAccessWhiteLabel } from '../src/lib/billing/plans';
import { apiKeyRateLimiter } from '../src/lib/auth/apiKeyAuth';

describe('Roadmap C.1: Billing & Subscription Management', () => {
  const orgId = 'org-billing-test-01';
  const ownerId = 'user-billing-owner-01';
  const viewerId = 'user-billing-viewer-01';
  let ownerCookie: string;
  let viewerCookie: string;
  const webhookSecret = 'whsec_test_secret_for_billing_spec_12345';

  it('Setup: Initialize Organization, Users, and Sessions', async () => {
    // 1. Seed Free Org
    memoryStore.organizations.set(orgId, {
      _id: orgId,
      id: orgId,
      name: 'Billing Test Labs',
      slug: 'billing-test-labs',
      ownerId: ownerId,
      plan: 'FREE',
      scanQuotas: {
        maxMonitoredDomains: 1,
        dailyScanLimit: 2,
        concurrentScans: 1,
      },
      settings: {
        alertEmail: 'security@billing-test.com',
      },
      alertSettings: {
        sendToAdmins: true,
      },
      subscriptionStatus: 'ACTIVE',
      createdAt: new Date(),
    });

    // 2. Seed Owner User
    memoryStore.users.set(ownerId, {
      _id: ownerId,
      id: ownerId,
      email: 'owner@billing-test.com',
      name: 'Billing Owner',
      organizationMemberships: [
        {
          organizationId: orgId,
          role: 'OWNER',
          joinedAt: new Date(),
        },
      ],
    });

    const ownerToken = createSessionToken({
      userId: ownerId,
      email: 'owner@billing-test.com',
      organizationId: orgId,
      role: 'OWNER',
    });
    ownerCookie = `pliora_session=${ownerToken}`;

    // 3. Seed Viewer User
    memoryStore.users.set(viewerId, {
      _id: viewerId,
      id: viewerId,
      email: 'viewer@billing-test.com',
      name: 'Billing Viewer',
      organizationMemberships: [
        {
          organizationId: orgId,
          role: 'VIEWER',
          joinedAt: new Date(),
        },
      ],
    });

    const viewerToken = createSessionToken({
      userId: viewerId,
      email: 'viewer@billing-test.com',
      organizationId: orgId,
      role: 'VIEWER',
    });
    viewerCookie = `pliora_session=${viewerToken}`;
  });

  // =========================================================================
  // Test Group 1: Step Zero Quota Enforcement Audit (§1)
  // =========================================================================
  describe('1. Step Zero Quota Enforcement Audit (§1)', () => {
    it('maxMonitoredDomains: rejects adding root domains when quota is reached (403 QUOTA_EXCEEDED)', async () => {
      // Clear any prior assets
      for (const [k, v] of Array.from(memoryStore.assets.entries())) {
        if (v.organizationId === orgId) memoryStore.assets.delete(k);
      }

      // First domain: should succeed (count: 0 < 1)
      const req1 = new NextRequest('http://localhost:3000/api/assets', {
        method: 'POST',
        headers: { cookie: ownerCookie },
        body: JSON.stringify({ domain: 'domain1.billing-test.com' }),
      });
      const res1 = await addAsset(req1);
      assert.equal(res1.status, 201, 'First domain within maxMonitoredDomains quota succeeds');

      // Second domain: must be blocked (count: 1 >= 1)
      const req2 = new NextRequest('http://localhost:3000/api/assets', {
        method: 'POST',
        headers: { cookie: ownerCookie },
        body: JSON.stringify({ domain: 'domain2.billing-test.com' }),
      });
      const res2 = await addAsset(req2);
      assert.equal(res2.status, 403, 'Second domain exceeds maxMonitoredDomains quota and is blocked with 403');
      const body2 = await res2.json();
      assert.equal(body2.error?.code, 'QUOTA_EXCEEDED');
      assert.match(body2.error?.message, /limited to 1 monitored root domains/);
    });

    it('concurrentScans: rejects starting scan when active/queued scans hit limit (429 CONCURRENCY_LIMIT_REACHED)', async () => {
      // Seed an active verified asset
      const assetId = 'asset-quota-audit-01';
      memoryStore.assets.set(assetId, {
        _id: assetId,
        id: assetId,
        organizationId: orgId,
        fqdn: 'audit.billing-test.com',
        type: 'ROOT_DOMAIN',
        verificationStatus: 'VERIFIED',
      });

      // Seed 1 active scan (hitting concurrent limit = 1)
      const scanId = 'scan-active-01';
      memoryStore.scans.set(scanId, {
        _id: scanId,
        organizationId: orgId,
        assetId,
        status: 'ACTIVE',
        createdAt: new Date(),
      });

      const scanReq = new NextRequest('http://localhost:3000/api/scans', {
        method: 'POST',
        headers: { cookie: ownerCookie },
        body: JSON.stringify({ assetId, scanType: 'EXPOSURE' }),
      });
      const scanRes = await createScan(scanReq);
      assert.equal(scanRes.status, 429, 'Scan blocked with 429 when concurrent limit reached');
      const scanBody = await scanRes.json();
      assert.equal(scanBody.error?.code, 'CONCURRENCY_LIMIT_REACHED');

      // Clean up active scan
      memoryStore.scans.delete(scanId);
    });

    it('dailyScanLimit: rejects starting scan when 24-hour limit exceeded (429 DAILY_SCAN_LIMIT_EXCEEDED)', async () => {
      const assetId = 'asset-quota-audit-01';

      // Clear existing scans for org
      for (const [k, v] of Array.from(memoryStore.scans.entries())) {
        if (v.organizationId === orgId) memoryStore.scans.delete(k);
      }

      // Seed 2 scans created today (hitting dailyScanLimit = 2)
      memoryStore.scans.set('scan-daily-1', {
        _id: 'scan-daily-1',
        organizationId: orgId,
        assetId,
        status: 'COMPLETED',
        createdAt: new Date(),
      });
      memoryStore.scans.set('scan-daily-2', {
        _id: 'scan-daily-2',
        organizationId: orgId,
        assetId,
        status: 'COMPLETED',
        createdAt: new Date(),
      });

      const scanReq = new NextRequest('http://localhost:3000/api/scans', {
        method: 'POST',
        headers: { cookie: ownerCookie },
        body: JSON.stringify({ assetId, scanType: 'EXPOSURE' }),
      });
      const scanRes = await createScan(scanReq);
      assert.equal(scanRes.status, 429, 'Scan blocked with 429 when dailyScanLimit exceeded');
      const scanBody = await scanRes.json();
      assert.equal(scanBody.error?.code, 'DAILY_SCAN_LIMIT_EXCEEDED');

      // Clean up seeded scans
      memoryStore.scans.delete('scan-daily-1');
      memoryStore.scans.delete('scan-daily-2');
    });
  });

  // =========================================================================
  // Test Group 2: Payment Provider Checkout & Portal APIs (§2)
  // =========================================================================
  describe('2. Checkout & Customer Portal APIs (§2)', () => {
    it('POST /api/billing/checkout: blocks unauthenticated requests (401)', async () => {
      const req = new NextRequest('http://localhost:3000/api/billing/checkout', {
        method: 'POST',
        body: JSON.stringify({ plan: 'STARTER' }),
      });
      const res = await checkout(req);
      assert.equal(res.status, 401);
    });

    it('POST /api/billing/checkout: blocks VIEWER role with 403 Forbidden', async () => {
      const req = new NextRequest('http://localhost:3000/api/billing/checkout', {
        method: 'POST',
        headers: { cookie: viewerCookie },
        body: JSON.stringify({ plan: 'STARTER' }),
      });
      const res = await checkout(req);
      assert.equal(res.status, 403);
      const body = await res.json();
      assert.equal(body.error?.code, 'FORBIDDEN');
    });

    it('POST /api/billing/checkout: successfully creates checkout session for OWNER', async () => {
      const req = new NextRequest('http://localhost:3000/api/billing/checkout', {
        method: 'POST',
        headers: { cookie: ownerCookie },
        body: JSON.stringify({ plan: 'STARTER' }),
      });
      const res = await checkout(req);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.ok(body.data?.sessionId, 'Returns checkout sessionId');
      assert.ok(body.data?.url, 'Returns checkout redirection URL');
    });

    it('POST /api/billing/portal: generates customer portal URL for OWNER', async () => {
      const req = new NextRequest('http://localhost:3000/api/billing/portal', {
        method: 'POST',
        headers: { cookie: ownerCookie },
        body: JSON.stringify({ returnUrl: 'http://localhost:3000/dashboard/settings' }),
      });
      const res = await portal(req);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.ok(body.data?.url.includes('portal_session='), 'Returns customer portal URL');
    });
  });

  // =========================================================================
  // Test Group 3: Inbound Webhook Verification & Plan Synchronization (§3)
  // =========================================================================
  describe('3. Inbound Webhook Verification & Plan Synchronization (§3)', () => {
    function signPayload(payload: string, secret: string): string {
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const hmac = crypto
        .createHmac('sha256', secret)
        .update(`${timestamp}.${payload}`)
        .digest('hex');
      return `t=${timestamp},v1=${hmac}`;
    }

    it('POST /api/billing/webhook: rejects requests with invalid or missing signatures (400)', async () => {
      const payload = JSON.stringify({ type: 'checkout.session.completed' });
      const req = new NextRequest('http://localhost:3000/api/billing/webhook', {
        method: 'POST',
        headers: {
          'stripe-signature': 't=12345,v1=invalidsignature',
        },
        body: payload,
      });
      const res = await billingWebhook(req);
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.equal(body.error?.code, 'INVALID_WEBHOOK_SIGNATURE');
    });

    it('checkout.session.completed: upgrades organization plan and syncs quotas and AuditLog', async () => {
      const payload = JSON.stringify({
        id: 'evt_test_checkout_01',
        type: 'checkout.session.completed',
        data: {
          object: {
            client_reference_id: orgId,
            customer: 'cus_stripe_test_123',
            subscription: 'sub_stripe_test_456',
            metadata: {
              organizationId: orgId,
              plan: 'STARTER',
            },
          },
        },
        created: Math.floor(Date.now() / 1000),
      });

      const signature = signPayload(payload, webhookSecret);
      process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;

      const req = new NextRequest('http://localhost:3000/api/billing/webhook', {
        method: 'POST',
        headers: { 'stripe-signature': signature },
        body: payload,
      });

      const res = await billingWebhook(req);
      assert.equal(res.status, 200);
      const resBody = await res.json();
      assert.equal(resBody.received, true);
      assert.equal(resBody.action, 'SUBSCRIPTION_UPGRADED');

      // Verify Organization updated
      const updatedOrg = memoryStore.organizations.get(orgId);
      assert.equal(updatedOrg.plan, 'STARTER');
      assert.equal(updatedOrg.scanQuotas.maxMonitoredDomains, 5);
      assert.equal(updatedOrg.scanQuotas.dailyScanLimit, 25);
      assert.equal(updatedOrg.scanQuotas.concurrentScans, 2);
      assert.equal(updatedOrg.stripeCustomerId, 'cus_stripe_test_123');
      assert.equal(updatedOrg.stripeSubscriptionId, 'sub_stripe_test_456');
      assert.equal(updatedOrg.subscriptionStatus, 'ACTIVE');

      // Verify AuditLog recorded
      const auditLog = memoryStore.auditLogs.find(
        (a: any) => a.action === 'SUBSCRIPTION_UPGRADED' && a.objectId === orgId
      );
      assert.ok(auditLog, 'AuditLog entry created for SUBSCRIPTION_UPGRADED');
      assert.equal(auditLog.details.newPlan, 'STARTER');
    });

    it('invoice.payment_failed: initiates 7-day grace period, sets PAST_DUE, dispatches email & AuditLog', async () => {
      memoryStore.sentEmails = [];

      const payload = JSON.stringify({
        id: 'evt_test_payment_failed_01',
        type: 'invoice.payment_failed',
        data: {
          object: {
            id: 'in_failed_01',
            customer: 'cus_stripe_test_123',
            subscription: 'sub_stripe_test_456',
            attempt_count: 1,
          },
        },
        created: Math.floor(Date.now() / 1000),
      });

      const signature = signPayload(payload, webhookSecret);
      const req = new NextRequest('http://localhost:3000/api/billing/webhook', {
        method: 'POST',
        headers: { 'stripe-signature': signature },
        body: payload,
      });

      const res = await billingWebhook(req);
      assert.equal(res.status, 200);
      const resBody = await res.json();
      assert.equal(resBody.action, 'PAYMENT_FAILED_GRACE_PERIOD_STARTED');

      // Verify Organization state
      const org = memoryStore.organizations.get(orgId);
      assert.equal(org.subscriptionStatus, 'PAST_DUE');
      assert.ok(org.gracePeriodEnd, 'Grace period end timestamp is set');
      const diffDays = (new Date(org.gracePeriodEnd).getTime() - Date.now()) / (1000 * 3600 * 24);
      assert.ok(diffDays >= 6.8 && diffDays <= 7.1, 'Grace period is exactly 7 days');

      // Verify email dispatched
      const sentEmail = memoryStore.sentEmails.find((e: any) =>
        e.subject.includes('Payment Failed: 7-Day Grace Period Active')
      );
      assert.ok(sentEmail, 'Payment failure notification email dispatched to admin');

      // Verify AuditLog
      const auditLog = memoryStore.auditLogs.find(
        (a: any) => a.action === 'PAYMENT_FAILED_GRACE_PERIOD_STARTED' && a.objectId === orgId
      );
      assert.ok(auditLog, 'AuditLog entry created for PAYMENT_FAILED_GRACE_PERIOD_STARTED');
    });

    it('invoice.payment_succeeded: clears grace period and restores ACTIVE status', async () => {
      const payload = JSON.stringify({
        id: 'evt_test_payment_succeeded_01',
        type: 'invoice.payment_succeeded',
        data: {
          object: {
            id: 'in_success_01',
            customer: 'cus_stripe_test_123',
            subscription: 'sub_stripe_test_456',
          },
        },
        created: Math.floor(Date.now() / 1000),
      });

      const signature = signPayload(payload, webhookSecret);
      const req = new NextRequest('http://localhost:3000/api/billing/webhook', {
        method: 'POST',
        headers: { 'stripe-signature': signature },
        body: payload,
      });

      const res = await billingWebhook(req);
      assert.equal(res.status, 200);

      // Verify Organization state restored
      const org = memoryStore.organizations.get(orgId);
      assert.equal(org.subscriptionStatus, 'ACTIVE');
      assert.equal(org.gracePeriodEnd, undefined, 'Grace period end is cleared');
    });
  });

  // =========================================================================
  // Test Group 4: Downgrade & Over-Limit Handling (§4)
  // =========================================================================
  describe('4. Downgrade & Over-Limit Non-Destructive Handling (§4)', () => {
    it('customer.subscription.deleted: downgrades to FREE without deleting any existing assets', async () => {
      // Seed 3 verified assets while on Starter
      memoryStore.assets.set('asset-retained-1', {
        _id: 'asset-retained-1',
        organizationId: orgId,
        fqdn: 'site1.billing-test.com',
        type: 'ROOT_DOMAIN',
        verificationStatus: 'VERIFIED',
      });
      memoryStore.assets.set('asset-retained-2', {
        _id: 'asset-retained-2',
        organizationId: orgId,
        fqdn: 'site2.billing-test.com',
        type: 'ROOT_DOMAIN',
        verificationStatus: 'VERIFIED',
      });
      memoryStore.assets.set('asset-retained-3', {
        _id: 'asset-retained-3',
        organizationId: orgId,
        fqdn: 'site3.billing-test.com',
        type: 'ROOT_DOMAIN',
        verificationStatus: 'VERIFIED',
      });

      const payload = JSON.stringify({
        id: 'evt_test_sub_deleted_01',
        type: 'customer.subscription.deleted',
        data: {
          object: {
            id: 'sub_stripe_test_456',
            customer: 'cus_stripe_test_123',
          },
        },
        created: Math.floor(Date.now() / 1000),
      });

      const signature = crypto
        .createHmac('sha256', webhookSecret)
        .update(`${Math.floor(Date.now() / 1000)}.${payload}`)
        .digest('hex');

      const req = new NextRequest('http://localhost:3000/api/billing/webhook', {
        method: 'POST',
        headers: {
          'stripe-signature': `t=${Math.floor(Date.now() / 1000)},v1=${signature}`,
        },
        body: payload,
      });

      const res = await billingWebhook(req);
      assert.equal(res.status, 200);

      // Verify Org is downgraded to FREE
      const org = memoryStore.organizations.get(orgId);
      assert.equal(org.plan, 'FREE');
      assert.equal(org.subscriptionStatus, 'CANCELED');
      assert.equal(org.scanQuotas.maxMonitoredDomains, 1);

      // NON-DESTRUCTIVE VERIFICATION (§4):
      assert.ok(memoryStore.assets.has('asset-retained-1'), 'Asset 1 preserved');
      assert.ok(memoryStore.assets.has('asset-retained-2'), 'Asset 2 preserved');
      assert.ok(memoryStore.assets.has('asset-retained-3'), 'Asset 3 preserved');

      // Adding 4th asset is now blocked because count (3) >= FREE limit (1)
      const addReq = new NextRequest('http://localhost:3000/api/assets', {
        method: 'POST',
        headers: { cookie: ownerCookie },
        body: JSON.stringify({ domain: 'overflow.billing-test.com' }),
      });
      const addRes = await addAsset(addReq);
      assert.equal(addRes.status, 403, 'Adding domain in over-limit downgraded state is rejected');

      // Verify GET /api/billing/subscription returns over-limit warning
      const subReq = new NextRequest('http://localhost:3000/api/billing/subscription', {
        headers: { cookie: ownerCookie },
      });
      const subRes = await getSubscription(subReq);
      assert.equal(subRes.status, 200);
      const subBody = await subRes.json();
      assert.equal(subBody.data.domainUsage.isOverLimit, true);
      assert.ok(subBody.data.domainUsage.warningMessage.includes('exceeding your Free limit'));
    });
  });

  // =========================================================================
  // Test Group 5: Tier-Gated Features Server-Side Enforcement (§5)
  // =========================================================================
  describe('5. Tier-Gated Features Server-Side Enforcement (§5)', () => {
    it('White-Label PDF Branding: Free tier cannot enable white-label branding via PATCH /api/org', async () => {
      const req = new NextRequest('http://localhost:3000/api/org', {
        method: 'PATCH',
        headers: { cookie: ownerCookie },
        body: JSON.stringify({
          reportBranding: {
            whiteLabelEnabled: true,
            customName: 'Custom Brand Security',
          },
        }),
      });

      const res = await updateOrg(req);
      assert.equal(res.status, 403, 'Free tier is blocked from enabling white-label branding');
      const body = await res.json();
      assert.equal(body.error?.code, 'UPGRADE_REQUIRED');
    });

    it('White-Label PDF Reports: Free tier forces standard PLIŌRA branding even if flag set', async () => {
      // Force whiteLabelEnabled in memory to test server-side report generation defense
      const org = memoryStore.organizations.get(orgId);
      org.reportBranding = {
        whiteLabelEnabled: true,
        customName: 'Hacked Brand',
      };
      org.plan = 'FREE';

      const req = new NextRequest('http://localhost:3000/api/reports/export', {
        headers: { cookie: ownerCookie },
      });
      const res = await exportReport(req);
      assert.equal(res.status, 200);
      const buffer = await res.arrayBuffer();
      const pdfText = Buffer.from(buffer).toString('latin1');
      assert.ok(pdfText.includes('PLI'), 'Report contains PLIORA branding');
      assert.ok(!pdfText.includes('Hacked Brand'), 'Report ignores unauthorized custom branding on Free tier');
    });

    it('White-Label PDF Reports: Business tier respects white-label branding', async () => {
      const org = memoryStore.organizations.get(orgId);
      org.plan = 'BUSINESS';
      org.reportBranding = {
        whiteLabelEnabled: true,
        customName: 'Enterprise MSSP Shield',
      };

      const req = new NextRequest('http://localhost:3000/api/reports/export', {
        headers: { cookie: ownerCookie },
      });
      const res = await exportReport(req);
      assert.equal(res.status, 200);
      const buffer = await res.arrayBuffer();
      const pdfText = Buffer.from(buffer).toString('latin1');
      assert.ok(pdfText.includes('Enterprise MSSP Shield'), 'Business tier report contains custom white-label branding');
    });

    it('Customer API Key Rate Limits: Parameterized by Organization Tier (§A.5 & §5)', async () => {
      apiKeyRateLimiter.resetForTesting();

      assert.equal(getApiRateLimit('FREE'), 20, 'Free tier rate limit is 20 req/min');
      assert.equal(getApiRateLimit('STARTER'), 120, 'Starter tier rate limit is 120 req/min');
      assert.equal(getApiRateLimit('BUSINESS'), 300, 'Business tier rate limit is 300 req/min');
      assert.equal(getApiRateLimit('PRO'), 600, 'Pro tier rate limit is 600 req/min');

      // Test Free tier hitting rate limit at 20
      const testKeyId = 'key-rate-limit-test-01';
      for (let i = 0; i < 20; i++) {
        const check = apiKeyRateLimiter.checkRateLimit(testKeyId, getApiRateLimit('FREE'));
        assert.equal(check.allowed, true, `Request ${i + 1} is allowed`);
      }

      // 21st request: blocked
      const blockedCheck = apiKeyRateLimiter.checkRateLimit(testKeyId, getApiRateLimit('FREE'));
      assert.equal(blockedCheck.allowed, false, '21st request blocked for Free tier');
      assert.equal(blockedCheck.limit, 20);
    });
  });
});
