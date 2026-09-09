import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { NextRequest } from 'next/server';
import {
  connectToDatabase,
  assertDatabaseConnectionAtStartup,
  getStorageBackendInfo,
  isGuardrailEnforced,
  resetDatabaseConnectionForTesting,
} from '../src/lib/db';
import { memoryStore } from '../src/lib/store';
import { GET as getHealth } from '../src/app/api/health/route';
import { GET as getMetrics } from '../src/app/api/metrics/route';
import { logger, redactSensitiveData } from '../src/lib/observability/logger';
import { errorTracker } from '../src/lib/observability/errorTracker';
import { metrics } from '../src/lib/observability/metrics';
import { retentionService } from '../src/lib/retention/service';

describe('Roadmap C.2 & C.3: Production Hardening & Compliance Closeout', () => {
  // =========================================================================
  // Test Group 1: Memory-Store Production Guardrail (§1)
  // =========================================================================
  describe('1. Memory-Store Production Guardrail (§1)', () => {
    it('Refuses to silently fall back to in-memory store in production environment', async () => {
      const origNodeEnv = process.env.NODE_ENV;
      const origAllow = process.env.ALLOW_IN_MEMORY_STORE;
      const origForce = process.env.FORCE_MEMORY_STORE;

      try {
        (process.env as any).NODE_ENV = 'production';
        delete process.env.ALLOW_IN_MEMORY_STORE;
        process.env.FORCE_MEMORY_STORE = 'true';
        resetDatabaseConnectionForTesting();

        assert.strictEqual(isGuardrailEnforced(), true, 'Guardrail must be enforced in production when ALLOW_IN_MEMORY_STORE is unset');

        await assert.rejects(
          async () => {
            await connectToDatabase();
          },
          /FATAL PRODUCTION ERROR/,
          'connectToDatabase must throw fatal error in production when attempting to use in-memory store'
        );

        await assert.rejects(
          async () => {
            await assertDatabaseConnectionAtStartup();
          },
          /FATAL PRODUCTION ERROR/,
          'assertDatabaseConnectionAtStartup must reject boot in production'
        );
      } finally {
        (process.env as any).NODE_ENV = origNodeEnv;
        if (origAllow !== undefined) process.env.ALLOW_IN_MEMORY_STORE = origAllow;
        else delete process.env.ALLOW_IN_MEMORY_STORE;
        if (origForce !== undefined) process.env.FORCE_MEMORY_STORE = origForce;
        else delete process.env.FORCE_MEMORY_STORE;
        resetDatabaseConnectionForTesting();
      }
    });

    it('Permits graceful in-memory fallback in development/test environment', async () => {
      const origNodeEnv = process.env.NODE_ENV;
      const origForce = process.env.FORCE_MEMORY_STORE;

      try {
        (process.env as any).NODE_ENV = 'test';
        process.env.FORCE_MEMORY_STORE = 'true';
        resetDatabaseConnectionForTesting();

        assert.strictEqual(isGuardrailEnforced(), false, 'Guardrail must not block in test environment');
        const conn = await connectToDatabase();
        assert.strictEqual(conn, null, 'Fallback returns null in test environment');

        const startupInfo = await assertDatabaseConnectionAtStartup();
        assert.strictEqual(startupInfo.backend, 'in-memory');
        assert.strictEqual(startupInfo.status, 'fallback');

        const storageInfo = getStorageBackendInfo();
        assert.strictEqual(storageInfo.backend, 'in-memory');
        assert.strictEqual(storageInfo.isAvailable, false);
      } finally {
        (process.env as any).NODE_ENV = origNodeEnv;
        if (origForce !== undefined) process.env.FORCE_MEMORY_STORE = origForce;
        else delete process.env.FORCE_MEMORY_STORE;
        resetDatabaseConnectionForTesting();
      }
    });

    it('GET /api/health: accurately reports storage backend, subsystem statuses, and guardrail enforcement', async () => {
      const res = await getHealth();
      assert.strictEqual(res.status, 200);
      const json = await res.json();

      assert.ok(json.timestamp);
      assert.strictEqual(typeof json.uptimeSeconds, 'number');
      assert.ok(json.storage);
      assert.strictEqual(json.storage.backend, 'in-memory');
      assert.ok(json.storage.policy);
      assert.ok(json.subsystems.database);
      assert.ok(json.subsystems.queue);
      assert.ok(json.subsystems.aiAnalyst);
      assert.ok(json.subsystems.billing);
    });

    it('GET /api/health: returns HTTP 503 if database fails while guardrail is active', async () => {
      const origNodeEnv = process.env.NODE_ENV;
      const origAllow = process.env.ALLOW_IN_MEMORY_STORE;

      try {
        (process.env as any).NODE_ENV = 'production';
        delete process.env.ALLOW_IN_MEMORY_STORE;
        resetDatabaseConnectionForTesting();

        const res = await getHealth();
        assert.strictEqual(res.status, 503, 'Must return 503 Service Unavailable when DB is down under production guardrail');
        const json = await res.json();
        assert.strictEqual(json.status, 'unhealthy');
        assert.strictEqual(json.storage.guardrailEnforced, true);
      } finally {
        (process.env as any).NODE_ENV = origNodeEnv;
        if (origAllow !== undefined) process.env.ALLOW_IN_MEMORY_STORE = origAllow;
        else delete process.env.ALLOW_IN_MEMORY_STORE;
        resetDatabaseConnectionForTesting();
      }
    });
  });

  // =========================================================================
  // Test Group 2: Structured Logging & Secrets Redaction (§2 & §3)
  // =========================================================================
  describe('2. Structured Logging & Secrets Redaction (§2 & §3)', () => {
    it('Automatically scrubs Stripe live secrets from log messages and nested objects', () => {
      const sensitiveString = 'Error charging customer: ' + ['sk', 'live', '51M0MockStripeSecretKey998877665544332211'].join('_') + ' for org-1';
      const sanitized = redactSensitiveData(sensitiveString);
      assert.ok(!sanitized.includes('51M0MockStripeSecretKey'));
      assert.ok(sanitized.includes('sk_live_[REDACTED]'));

      const sensitiveObject = {
        name: 'StripeConfig',
        apiKey: 'plk_live_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5',
        description: 'Loaded with customer key plk_live_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5 for scanning',
        stripeSecret: ['sk', 'live', '1234567890abcdefghijklmnop'].join('_'),
        nested: {
          password: 'super_secret_db_password_123',
          normalField: 'hello-world',
        },
      };

      const sanitizedObj = redactSensitiveData(sensitiveObject);
      assert.strictEqual(sanitizedObj.apiKey, '[REDACTED]', 'Field with sensitive key name must be redacted');
      assert.strictEqual(sanitizedObj.description, 'Loaded with customer key plk_live_[REDACTED] for scanning', 'String value in normal field must be regex-scrubbed');
      assert.strictEqual(sanitizedObj.stripeSecret, '[REDACTED]');
      assert.strictEqual(sanitizedObj.nested.password, '[REDACTED]');
      assert.strictEqual(sanitizedObj.nested.normalField, 'hello-world');
    });

    it('Automatically redacts database connection strings containing user/password credentials', () => {
      const mongoUri = 'mongodb+srv://admin_user:P@ssword12345!@cluster0.abcde.mongodb.net/production_db';
      const sanitizedUri = redactSensitiveData(mongoUri);
      assert.ok(!sanitizedUri.includes('P@ssword12345!'));
      assert.ok(sanitizedUri.includes('[REDACTED]'));

      const redisUri = 'redis://default:mySecretRedisPass@redis.internal:6379';
      const sanitizedRedis = redactSensitiveData(redisUri);
      assert.ok(!sanitizedRedis.includes('mySecretRedisPass'));
      assert.ok(sanitizedRedis.includes('[REDACTED]'));
    });

    it('Logger records redacted entries into buffer and preserves clean messages', () => {
      logger.clearLogsForTesting();
      logger.info('System initiated scan with API key plk_live_99887766554433221100aa', {
        userSecret: 'secret_user_token_abc',
        publicId: 'asset-123',
      });

      const recent = logger.getRecentLogs();
      assert.strictEqual(recent.length, 1);
      assert.ok(!recent[0].message.includes('plk_live_99887766554433221100aa'));
      assert.ok(recent[0].message.includes('plk_live_[REDACTED]'));
      assert.strictEqual(recent[0].context?.userSecret, '[REDACTED]');
      assert.strictEqual(recent[0].context?.publicId, 'asset-123');
    });
  });

  // =========================================================================
  // Test Group 3: Error Tracking Priority Categories (§2)
  // =========================================================================
  describe('3. Error Tracking Priority Categories (§2)', () => {
    it('Captures and categorizes SCAN_PIPELINE_FAILURE', () => {
      errorTracker.clearForTesting();
      errorTracker.captureScanFailure('scan-001', 'target.corp.com', new Error('Connection reset by peer'), 'org-test');

      const events = errorTracker.getRecordedEvents();
      assert.strictEqual(events.length, 1);
      assert.strictEqual(events[0].category, 'SCAN_PIPELINE_FAILURE');
      assert.strictEqual(events[0].context.scanId, 'scan-001');
      assert.strictEqual(events[0].context.targetFqdn, 'target.corp.com');
      assert.strictEqual(events[0].organizationId, 'org-test');
    });

    it('Captures and categorizes AI_PROVIDER_FALLBACK', () => {
      errorTracker.clearForTesting();
      errorTracker.captureAIFallback('finding-cve-001', 'Grounding validation rejected hallucinated CVE', undefined, 'org-test');

      const events = errorTracker.getRecordedEvents();
      assert.strictEqual(events.length, 1);
      assert.strictEqual(events[0].category, 'AI_PROVIDER_FALLBACK');
      assert.strictEqual(events[0].context.objectId, 'finding-cve-001');
      assert.strictEqual(events[0].context.reason, 'Grounding validation rejected hallucinated CVE');
    });

    it('Captures and categorizes ALERT_DELIVERY_FAILURE', () => {
      errorTracker.clearForTesting();
      errorTracker.captureAlertDeliveryFailure('SLACK', 'https://hooks.slack.com/services/T00/B00/X00', new Error('HTTP 404 Webhook Not Found'), 'org-test');

      const events = errorTracker.getRecordedEvents();
      assert.strictEqual(events.length, 1);
      assert.strictEqual(events[0].category, 'ALERT_DELIVERY_FAILURE');
      assert.strictEqual(events[0].context.channel, 'SLACK');
    });

    it('Captures and categorizes BILLING_WEBHOOK_ERROR with automatic secret scrubbing', () => {
      errorTracker.clearForTesting();
      errorTracker.captureBillingWebhookError(
        'invoice.payment_failed',
        'evt_123',
        new Error('Payment failed with customer secret ' + ['sk', 'live', 'secret_leaked_in_trace_998877'].join('_')),
        'org-test'
      );

      const events = errorTracker.getRecordedEvents();
      assert.strictEqual(events.length, 1);
      assert.strictEqual(events[0].category, 'BILLING_WEBHOOK_ERROR');
      assert.strictEqual(events[0].context.eventType, 'invoice.payment_failed');
      assert.ok(!events[0].message.includes('sk_live_secret_leaked'));
      assert.ok(events[0].message.includes('sk_live_[REDACTED]'));
    });
  });

  // =========================================================================
  // Test Group 4: Core Metrics Aggregation & Telemetry (§2)
  // =========================================================================
  describe('4. Core Metrics Aggregation & Telemetry (§2)', () => {
    it('Tracks scan metrics, alert delivery rates, and AI fallback rates accurately', () => {
      metrics.resetForTesting();

      // Scans
      metrics.recordScanStarted();
      metrics.recordScanCompleted('COMPLETED', 1200);
      metrics.recordScanStarted();
      metrics.recordScanCompleted('FAILED', 400);

      // Alerts
      metrics.recordAlertDelivery('EMAIL', true);
      metrics.recordAlertDelivery('EMAIL', false);
      metrics.recordAlertDelivery('SLACK', true);

      // AI Explanations
      metrics.recordAIRequest(true, false, false);
      metrics.recordAIRequest(false, true, true);

      // Billing
      metrics.recordBillingWebhook('checkout.session.completed', true);
      metrics.recordCheckoutSessionCreated();
      metrics.recordPortalSessionCreated();

      const snapshot = metrics.getMetricsSnapshot();

      // Verify scans
      assert.strictEqual(snapshot.scans.totalStarted, 2);
      assert.strictEqual(snapshot.scans.succeeded, 1);
      assert.strictEqual(snapshot.scans.failed, 1);
      assert.strictEqual(snapshot.scans.averageDurationMs, 800);

      // Verify alerts
      assert.strictEqual(snapshot.alerts.totalAttempted, 3);
      assert.strictEqual(snapshot.alerts.totalSucceeded, 2);
      assert.strictEqual(snapshot.alerts.totalFailed, 1);
      assert.strictEqual(snapshot.alerts.byChannel.EMAIL.successRatePercent, 50);
      assert.strictEqual(snapshot.alerts.byChannel.SLACK.successRatePercent, 100);

      // Verify AI fallback rate (1 fallback out of 2 requests = 50%)
      assert.strictEqual(snapshot.aiAnalyst.totalRequests, 2);
      assert.strictEqual(snapshot.aiAnalyst.fallbacksTriggered, 1);
      assert.strictEqual(snapshot.aiAnalyst.groundingRejections, 1);
      assert.strictEqual(snapshot.aiAnalyst.fallbackRatePercent, 50);

      // Verify billing
      assert.strictEqual(snapshot.billing.webhooksProcessed, 1);
      assert.strictEqual(snapshot.billing.checkoutSessionsCreated, 1);
      assert.strictEqual(snapshot.billing.portalSessionsCreated, 1);

      // Verify external API usage is connected
      assert.ok(snapshot.externalApiUsage);
    });

    it('GET /api/metrics: returns telemetry payload', async () => {
      const req = new NextRequest('http://localhost:3000/api/metrics');
      const res = await getMetrics(req);
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.success, true);
      assert.ok(json.data.scans);
      assert.ok(json.data.alerts);
      assert.ok(json.data.aiAnalyst);
      assert.ok(json.data.billing);
    });
  });

  // =========================================================================
  // Test Group 5: Evidence & Tenant Data Retention Policy (§9)
  // =========================================================================
  describe('5. Evidence & Data Retention Policy (§9)', () => {
    it('Prunes raw evidence records older than retention window while preserving recent evidence', async () => {
      memoryStore.evidence.clear();

      const oldDate = new Date(Date.now() - 95 * 24 * 60 * 60 * 1000); // 95 days old
      const freshDate = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000); // 10 days old

      memoryStore.evidence.set('ev-old-01', {
        id: 'ev-old-01',
        organizationId: 'org-1',
        checkType: 'DNS_RECORD',
        rawObservation: { heavy: 'dump-from-3-months-ago' },
        observedAt: oldDate,
        createdAt: oldDate,
      });

      memoryStore.evidence.set('ev-fresh-01', {
        id: 'ev-fresh-01',
        organizationId: 'org-1',
        checkType: 'TLS_HANDSHAKE',
        rawObservation: { cipher: 'TLS_AES_256_GCM_SHA384' },
        observedAt: freshDate,
        createdAt: freshDate,
      });

      assert.strictEqual(memoryStore.evidence.size, 2);

      // Run 90-day retention prune
      const res = await retentionService.pruneExpiredEvidence(90);
      assert.strictEqual(res.prunedCount, 1);
      assert.strictEqual(memoryStore.evidence.size, 1);
      assert.strictEqual(memoryStore.evidence.has('ev-fresh-01'), true);
      assert.strictEqual(memoryStore.evidence.has('ev-old-01'), false);
    });

    it('Prunes assets and scans for cancelled organizations past grace window and records AuditLog', async () => {
      const cancelledOrgId = 'org-cancelled-test-99';
      const pastGraceEnd = new Date(Date.now() - 40 * 24 * 60 * 60 * 1000); // 40 days ago

      memoryStore.organizations.set(cancelledOrgId, {
        _id: cancelledOrgId,
        id: cancelledOrgId,
        name: 'Cancelled Labs',
        slug: 'cancelled-labs',
        subscriptionStatus: 'CANCELED',
        currentPeriodEnd: pastGraceEnd,
        createdAt: new Date(),
      });

      memoryStore.assets.set('asset-cand-01', {
        _id: 'asset-cand-01',
        id: 'asset-cand-01',
        organizationId: cancelledOrgId,
        fqdn: 'cancelled-asset.com',
        type: 'ROOT_DOMAIN',
        verificationStatus: 'VERIFIED',
      });

      // Run 30-day cancelled tenant cleanup
      const res = await retentionService.pruneCancelledTenantData(30);
      assert.ok(res.prunedOrgs.includes(cancelledOrgId));
      assert.strictEqual(res.assetsDeleted, 1);
      assert.strictEqual(memoryStore.assets.has('asset-cand-01'), false);

      const retentionAudit = memoryStore.auditLogs.find(
        (l) => l.action === 'CANCELLED_TENANT_DATA_PRUNED' && l.organizationId === cancelledOrgId
      );
      assert.ok(retentionAudit, 'Must record AuditLog entry for cancelled tenant data purge');
    });

    it('runRetentionCleanup executes full automated retention cycle', async () => {
      const summary = await retentionService.runRetentionCleanup();
      assert.ok(summary.timestamp);
      assert.strictEqual(typeof summary.evidencePruned, 'number');
      assert.strictEqual(typeof summary.cancelledOrgsPruned, 'number');
      assert.strictEqual(typeof summary.assetsDeleted, 'number');
    });
  });
});
