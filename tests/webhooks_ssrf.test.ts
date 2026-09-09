import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { NextRequest } from 'next/server';
import { resolveAndPinTarget } from '../src/lib/security';
import { memoryStore } from '../src/lib/store';
import { createSessionToken } from '../src/lib/auth';
import { GET as listWebhooks, POST as createWebhook } from '../src/app/api/org/webhooks/route';
import { GET as getWebhook, PATCH as updateWebhook, DELETE as deleteWebhook } from '../src/app/api/org/webhooks/[id]/route';

describe('Webhook Delivery & SSRF Validation (§A.4)', () => {
  const orgId = 'org_webhook_ssrf_test';
  const ownerUserId = 'user_webhook_owner';
  let ownerCookie: string;

  it('Setup: Initialize Organization and Session', async () => {
    memoryStore.organizations.set(orgId, {
      _id: orgId,
      id: orgId,
      name: 'Webhook SSRF Test Org',
      slug: 'webhook-ssrf-test',
      ownerId: ownerUserId,
      plan: 'ENTERPRISE',
      createdAt: new Date(),
    });

    memoryStore.users.set(ownerUserId, {
      _id: ownerUserId,
      id: ownerUserId,
      name: 'Webhook Owner',
      email: 'owner@webhook-ssrf.test',
      globalRole: 'USER',
      activeOrganizationId: orgId,
      organizationMemberships: [
        {
          organizationId: orgId,
          role: 'OWNER',
          joinedAt: new Date(),
        },
      ],
    });

    const token = await createSessionToken({
      userId: ownerUserId,
      email: 'owner@webhook-ssrf.test',
      organizationId: orgId,
      role: 'OWNER',
    });
    ownerCookie = `session=${token}`;
  });

  it('SSRF Guard: Rejects loopback, link-local, and private RFC1918 IPs directly', async () => {
    const maliciousTargets = [
      '127.0.0.1',
      '127.0.0.2',
      'localhost',
      '169.254.169.254',
      '10.0.0.1',
      '10.254.0.1',
      '172.16.0.1',
      '172.31.255.255',
      '192.168.1.1',
      '0.0.0.0',
    ];

    for (const target of maliciousTargets) {
      await assert.rejects(
        async () => {
          await resolveAndPinTarget(target);
        },
        (err: any) => {
          const msg = (err.message || '').toLowerCase();
          return msg.includes('ssrf') || msg.includes('private') || msg.includes('loopback') || msg.includes('reserved');
        },
        `Expected target ${target} to be blocked by resolveAndPinTarget`
      );
    }
  });

  it('POST /api/org/webhooks: Blocks SSRF targets with HTTP 400 and SSRF_VALIDATION_FAILED', async () => {
    const maliciousUrls = [
      'http://127.0.0.1:8080/internal-webhook',
      'http://localhost:3000/api/admin',
      'http://169.254.169.254/latest/meta-data/',
      'http://10.1.2.3/receive-alerts',
      'http://192.168.0.10/admin',
    ];

    for (const url of maliciousUrls) {
      const req = new NextRequest('http://localhost:3000/api/org/webhooks', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: ownerCookie,
        },
        body: JSON.stringify({
          name: 'Malicious Webhook',
          url,
          format: 'JSON',
          enabledTypes: ['NEW_CRITICAL_FINDING'],
        }),
      });

      const res = await createWebhook(req);
      assert.strictEqual(res.status, 400);
      const json = await res.json();
      assert.strictEqual(json.success, false);
      assert.strictEqual(json.error.code, 'SSRF_VALIDATION_FAILED');
    }
  });

  let createdWebhookId: string;
  let rawSecret: string;

  it('POST /api/org/webhooks: Successfully registers valid external webhook with secret', async () => {
    const req = new NextRequest('http://localhost:3000/api/org/webhooks', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: ownerCookie,
      },
      body: JSON.stringify({
        name: 'Production Slack & PagerDuty',
        url: 'https://webhook.site/00000000-0000-0000-0000-000000000000',
        format: 'JSON',
        enabledTypes: ['NEW_CRITICAL_FINDING', 'THREAT_DETECTED'],
      }),
    });

    const res = await createWebhook(req);
    assert.strictEqual(res.status, 201);
    const json = await res.json();
    assert.strictEqual(json.success, true);
    assert.ok(json.data._id);
    assert.ok(json.data.secret.startsWith('whsec_live_'));
    assert.strictEqual(json.data.name, 'Production Slack & PagerDuty');
    assert.strictEqual(json.data.format, 'JSON');

    createdWebhookId = json.data._id;
    rawSecret = json.data.secret;
  });

  it('GET /api/org/webhooks: Lists registered webhooks with masked secrets', async () => {
    const req = new NextRequest('http://localhost:3000/api/org/webhooks', {
      method: 'GET',
      headers: {
        Cookie: ownerCookie,
      },
    });

    const res = await listWebhooks(req);
    assert.strictEqual(res.status, 200);
    const json = await res.json();
    assert.strictEqual(json.success, true);
    assert.ok(Array.isArray(json.data));
    const found = json.data.find((w: any) => w._id === createdWebhookId);
    assert.ok(found);
    assert.strictEqual(found.name, 'Production Slack & PagerDuty');
    assert.ok(found.secret.endsWith('****'));
    assert.notStrictEqual(found.secret, rawSecret);
  });

  it('PATCH /api/org/webhooks/[id]: Rejects updating URL to private IP', async () => {
    const req = new NextRequest(`http://localhost:3000/api/org/webhooks/${createdWebhookId}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Cookie: ownerCookie,
      },
      body: JSON.stringify({
        url: 'http://127.0.0.1:9000/hook',
      }),
    });

    const res = await updateWebhook(req, { params: Promise.resolve({ id: createdWebhookId }) });
    assert.strictEqual(res.status, 400);
    const json = await res.json();
    assert.strictEqual(json.success, false);
    assert.strictEqual(json.error.code, 'SSRF_VALIDATION_FAILED');
  });

  it('PATCH /api/org/webhooks/[id]: Successfully updates webhook format and active status', async () => {
    const req = new NextRequest(`http://localhost:3000/api/org/webhooks/${createdWebhookId}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Cookie: ownerCookie,
      },
      body: JSON.stringify({
        format: 'SLACK',
        name: 'Updated Slack Hook',
      }),
    });

    const res = await updateWebhook(req, { params: Promise.resolve({ id: createdWebhookId }) });
    assert.strictEqual(res.status, 200);
    const json = await res.json();
    assert.strictEqual(json.success, true);
    assert.strictEqual(json.data.format, 'SLACK');
    assert.strictEqual(json.data.name, 'Updated Slack Hook');
  });

  it('DELETE /api/org/webhooks/[id]: Deletes the webhook endpoint', async () => {
    const req = new NextRequest(`http://localhost:3000/api/org/webhooks/${createdWebhookId}`, {
      method: 'DELETE',
      headers: {
        Cookie: ownerCookie,
      },
    });

    const res = await deleteWebhook(req, { params: Promise.resolve({ id: createdWebhookId }) });
    assert.strictEqual(res.status, 200);
    const json = await res.json();
    assert.strictEqual(json.success, true);

    // Verify it's gone
    const verifyReq = new NextRequest('http://localhost:3000/api/org/webhooks', {
      method: 'GET',
      headers: {
        Cookie: ownerCookie,
      },
    });
    const verifyRes = await listWebhooks(verifyReq);
    const verifyJson = await verifyRes.json();
    const remaining = verifyJson.data.find((w: any) => w._id === createdWebhookId);
    assert.strictEqual(remaining, undefined);
  });
});
