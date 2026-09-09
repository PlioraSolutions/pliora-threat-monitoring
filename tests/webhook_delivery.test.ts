import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { memoryStore } from '../src/lib/store';
import {
  formatSlackBlockKit,
  verifyWebhookSignature,
  sendWebhookAlert,
  WebhookAlertPayload,
} from '../src/lib/alerts/webhook';
import { triggerAlert } from '../src/lib/alerts/service';

describe('Webhook Delivery & Signature Verification (§A.4)', () => {
  const secret = 'whsec_live_test_secret_1234567890abcdef';

  const samplePayload: WebhookAlertPayload = {
    event: 'NEW_CRITICAL_FINDING',
    severity: 'CRITICAL',
    title: 'Critical Vulnerability Detected: Apache Path Traversal',
    summary: 'Vulnerable Apache HTTP Server 2.4.49 exposed on api.example.com',
    targetName: 'api.example.com',
    riskScore: 92,
    findingTitle: 'Apache HTTP Server 2.4.49 Path Traversal (CVE-2021-41773)',
    remediationSummary: 'Upgrade Apache HTTP Server to version 2.4.51 or later immediately.',
    dashboardUrl: 'https://app.pliora.io/dashboard/findings/find-123',
    timestamp: new Date().toISOString(),
  };

  it('Slack Formatting: Generates compliant Block Kit payload with correct severity accent', () => {
    const slackPayload = formatSlackBlockKit(samplePayload);

    assert.ok(slackPayload.attachments, 'Must contain attachments array');
    assert.strictEqual(slackPayload.attachments.length, 1);

    const attachment = slackPayload.attachments[0];
    assert.strictEqual(attachment.color, '#ef4444', 'CRITICAL alert must have red accent (#ef4444)');

    const blocks = attachment.blocks;
    assert.ok(blocks.length >= 4, 'Must have header, section fields, details, and context');

    const header: any = blocks.find((b: any) => b.type === 'header');
    assert.ok(header);
    assert.ok(header.text?.text?.includes('CRITICAL Alert:'));

    const sectionWithFields: any = blocks.find((b: any) => b.fields);
    assert.ok(sectionWithFields);
    assert.ok(sectionWithFields.fields?.some((f: any) => f.text.includes('api.example.com')));
    assert.ok(sectionWithFields.fields?.some((f: any) => f.text.includes('92')));

    const remediationSection: any = blocks.find(
      (b: any) => b.text && b.text.text?.includes('Recommended Action:')
    );
    assert.ok(remediationSection);
    assert.ok(remediationSection.text?.text?.includes('Upgrade Apache HTTP Server'));
  });

  it('Slack Formatting: Correctly maps HIGH and MEDIUM severities', () => {
    const highSlack = formatSlackBlockKit({ ...samplePayload, severity: 'HIGH' });
    assert.strictEqual(highSlack.attachments[0].color, '#f97316');

    const medSlack = formatSlackBlockKit({ ...samplePayload, severity: 'MEDIUM' });
    assert.strictEqual(medSlack.attachments[0].color, '#eab308');

    const lowSlack = formatSlackBlockKit({ ...samplePayload, severity: 'LOW' });
    assert.strictEqual(lowSlack.attachments[0].color, '#3b82f6');
  });

  it('HMAC Signature Verification: Successfully verifies genuine payload and signature', () => {
    const payloadStr = JSON.stringify(samplePayload);
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const signedPayload = `${timestamp}.${payloadStr}`;
    const hmacHex = crypto.createHmac('sha256', secret).update(signedPayload).digest('hex');
    const signatureHeader = `t=${timestamp},v1=${hmacHex}`;

    const result = verifyWebhookSignature(payloadStr, signatureHeader, secret);
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.reason, undefined);
  });

  it('HMAC Signature Verification: Rejects tampered payload body', () => {
    const payloadStr = JSON.stringify(samplePayload);
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const signedPayload = `${timestamp}.${payloadStr}`;
    const hmacHex = crypto.createHmac('sha256', secret).update(signedPayload).digest('hex');
    const signatureHeader = `t=${timestamp},v1=${hmacHex}`;

    // Tamper with body
    const tamperedPayload = JSON.stringify({ ...samplePayload, riskScore: 10 });
    const result = verifyWebhookSignature(tamperedPayload, signatureHeader, secret);
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.reason, 'HMAC signature mismatch');
  });

  it('HMAC Signature Verification: Rejects incorrect secret', () => {
    const payloadStr = JSON.stringify(samplePayload);
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const signedPayload = `${timestamp}.${payloadStr}`;
    const hmacHex = crypto.createHmac('sha256', 'wrong_secret_abcdef').update(signedPayload).digest('hex');
    const signatureHeader = `t=${timestamp},v1=${hmacHex}`;

    const result = verifyWebhookSignature(payloadStr, signatureHeader, secret);
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.reason, 'HMAC signature mismatch');
  });

  it('HMAC Signature Verification: Rejects replay attacks outside tolerance window', () => {
    const payloadStr = JSON.stringify(samplePayload);
    // Timestamp from 10 minutes (600 seconds) ago
    const oldTimestamp = (Math.floor(Date.now() / 1000) - 600).toString();
    const signedPayload = `${oldTimestamp}.${payloadStr}`;
    const hmacHex = crypto.createHmac('sha256', secret).update(signedPayload).digest('hex');
    const signatureHeader = `t=${oldTimestamp},v1=${hmacHex}`;

    const result = verifyWebhookSignature(payloadStr, signatureHeader, secret, 300);
    assert.strictEqual(result.valid, false);
    assert.ok(result.reason?.includes('replay protection'));
  });

  it('HMAC Signature Verification: Rejects malformed headers', () => {
    const payloadStr = JSON.stringify(samplePayload);
    const result1 = verifyWebhookSignature(payloadStr, 'invalid_header', secret);
    assert.strictEqual(result1.valid, false);

    const result2 = verifyWebhookSignature(payloadStr, 't=12345', secret);
    assert.strictEqual(result2.valid, false);
  });

  it('Alert Coordinator: Dispatches to registered WebhookEndpoint and logs audit entry', async () => {
    const orgId = 'org_webhook_delivery_test';
    memoryStore.organizations.set(orgId, {
      _id: orgId,
      name: 'Alert Webhook Org',
      plan: 'ENTERPRISE',
      alertSettings: {
        enabledTypes: ['NEW_CRITICAL_FINDING'],
        minRiskScore: 50,
        additionalEmails: ['admin@example.com'],
      },
    });

    // Register webhook endpoint in memoryStore
    const webhookEndpointId = 'wh_endpoint_test_01';
    memoryStore.webhooks.set(webhookEndpointId, {
      _id: webhookEndpointId,
      organizationId: orgId,
      name: 'Security Ops Webhook',
      url: 'https://example.com/alerts/webhook', // Valid public external URL
      format: 'JSON',
      secret: 'whsec_live_ops_secret_9999',
      enabledTypes: ['NEW_CRITICAL_FINDING'],
      active: true,
      createdAt: new Date(),
    });

    const alertResult = await triggerAlert({
      type: 'NEW_CRITICAL_FINDING',
      organizationId: orgId,
      targetName: 'portal.example.com',
      finding: {
        _id: 'find_crit_01',
        title: 'Exposed Kubernetes Dashboard',
        severity: 'CRITICAL',
        confidence: 'CONFIRMED',
        riskScore: 90,
        description: 'Kubernetes dashboard accessible without authentication',
      },
      asset: {
        _id: 'asset_01',
        importance: 'CRITICAL',
      },
    });

    assert.strictEqual(alertResult.triggered, true);

    // Verify audit log has recorded either ALERT_WEBHOOK_DELIVERED or ALERT_WEBHOOK_FAILED
    const webhookAudit = memoryStore.auditLogs.find(
      (log) =>
        log.organizationId === orgId &&
        (log.action === 'ALERT_WEBHOOK_DELIVERED' || log.action === 'ALERT_WEBHOOK_FAILED')
    );

    assert.ok(webhookAudit, 'Alert coordinator must attempt webhook dispatch and log audit event');
    assert.strictEqual(webhookAudit.details.url, 'https://example.com/alerts/webhook');
    assert.strictEqual(webhookAudit.details.channel, 'JSON');
  });
});
