import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { NextRequest } from 'next/server';
import { memoryStore } from '../src/lib/store';
import { createSessionToken } from '../src/lib/auth';
import { POST as exportPdfOnDemand } from '../src/app/api/reports/executive-summary/pdf/route';
import { GET as exportReport } from '../src/app/api/reports/export/route';
import { sendMonthlyScheduledReport } from '../src/lib/reports/scheduledReports';

describe('PDF Report Generation Triggers (§4 & §5)', () => {
  const orgId = 'org_trigger_test';
  const ownerUserId = 'user_trigger_owner';
  let ownerCookie: string;

  it('Setup: Initialize Organization, Owner, and Session', async () => {
    memoryStore.organizations.set(orgId, {
      _id: orgId,
      id: orgId,
      name: 'Beacon Financial Corp',
      slug: 'beacon-financial',
      ownerId: ownerUserId,
      plan: 'ENTERPRISE',
      scheduledReports: {
        enabled: false, // OFF by default (§4)
        frequency: 'MONTHLY',
        recipients: ['ciso@beacon-financial.com'],
      },
      createdAt: new Date(),
    });

    memoryStore.users.set(ownerUserId, {
      _id: ownerUserId,
      id: ownerUserId,
      name: 'Beacon Admin',
      email: 'admin@beacon-financial.com',
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

    // Seed finding
    memoryStore.findings.set('f_trig_01', {
      _id: 'f_trig_01',
      organizationId: orgId,
      title: 'Subdomain Takeover on AWS S3 Bucket',
      findingCode: 'SUBDOMAIN-TAKEOVER-S3',
      severity: 'HIGH',
      confidence: 'CONFIRMED',
      status: 'OPEN',
      riskScore: 80,
      assetFqdn: 'cdn.beacon-financial.com',
      description: 'DNS CNAME points to an unclaimed Amazon S3 bucket.',
      createdAt: new Date(),
    });

    const token = await createSessionToken({
      userId: ownerUserId,
      email: 'admin@beacon-financial.com',
      organizationId: orgId,
      role: 'OWNER',
    });
    ownerCookie = `pliora_session=${token}`;
  });

  it('On-Demand Trigger: Rejects unauthenticated request with 401', async () => {
    const req = new NextRequest('http://localhost:3000/api/reports/executive-summary/pdf', {
      method: 'POST',
    });
    const res = await exportPdfOnDemand(req);
    assert.strictEqual(res.status, 401);
  });

  it('On-Demand Trigger: POST /api/reports/executive-summary/pdf returns PDF & logs AuditLog', async () => {
    const req = new NextRequest('http://localhost:3000/api/reports/executive-summary/pdf', {
      method: 'POST',
      headers: {
        Cookie: ownerCookie,
      },
    });

    const res = await exportPdfOnDemand(req);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.headers.get('content-type'), 'application/pdf');

    const disposition = res.headers.get('content-disposition');
    assert.ok(disposition?.includes('attachment; filename="pliora-security-report-beacon-financial-'));

    const arrayBuffer = await res.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    assert.ok(buffer.length > 3000);
    assert.strictEqual(buffer.subarray(0, 5).toString('ascii'), '%PDF-');

    // Verify AuditLog
    const audit = memoryStore.auditLogs.find(
      (log) =>
        log.organizationId === orgId &&
        log.action === 'REPORT_GENERATED' &&
        log.details?.trigger === 'ON_DEMAND'
    );
    assert.ok(audit, 'AuditLog must capture on-demand report generation event');
    assert.strictEqual(audit.details?.format, 'PDF');
    assert.strictEqual(audit.details?.reportType, 'EXECUTIVE_SUMMARY');
  });

  it('Export Route: GET /api/reports/export?format=pdf returns PDF buffer', async () => {
    const req = new NextRequest('http://localhost:3000/api/reports/export?format=pdf', {
      method: 'GET',
      headers: {
        Cookie: ownerCookie,
      },
    });

    const res = await exportReport(req);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.headers.get('content-type'), 'application/pdf');

    const arrayBuffer = await res.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    assert.strictEqual(buffer.subarray(0, 5).toString('ascii'), '%PDF-');
  });

  it('Scheduled Trigger (§4): Skips generation when scheduledReports is disabled (opt-in guard)', async () => {
    const res = await sendMonthlyScheduledReport(orgId);
    assert.strictEqual(res.triggered, false);
    assert.ok(res.reason?.includes('not enabled'));
  });

  it('Scheduled Trigger (§4): Dispatches PDF attachment via email when opt-in enabled', async () => {
    // Opt-in to scheduled reports
    const org = memoryStore.organizations.get(orgId);
    org.scheduledReports.enabled = true;
    memoryStore.organizations.set(orgId, org);

    const res = await sendMonthlyScheduledReport(orgId);
    assert.strictEqual(res.triggered, true);
    assert.strictEqual(res.success, true);
    assert.ok(res.recipients?.includes('ciso@beacon-financial.com'));

    // Verify sent email record in memoryStore
    const sent = memoryStore.sentEmails.find(
      (e) => e.to.includes('ciso@beacon-financial.com') && e.subject.includes('Monthly Security Risk Assessment')
    );
    assert.ok(sent, 'Email provider must have received monthly report message');
    assert.ok(Array.isArray(sent.attachments), 'Email must have attachments array');
    assert.strictEqual(sent.attachments.length, 1);

    const att = sent.attachments[0];
    assert.ok(att.filename.endsWith('.pdf'));
    assert.strictEqual(att.contentType, 'application/pdf');
    assert.ok(Buffer.isBuffer(att.content));
    assert.strictEqual(att.content.subarray(0, 5).toString('ascii'), '%PDF-');

    // Verify AuditLog
    const audit = memoryStore.auditLogs.find(
      (log) =>
        log.organizationId === orgId &&
        log.action === 'REPORT_GENERATED' &&
        log.details?.trigger === 'SCHEDULED'
    );
    assert.ok(audit, 'AuditLog must record scheduled report generation event');
    assert.strictEqual(audit.details?.trigger, 'SCHEDULED');

    // Verify lastSentAt updated
    const updatedOrg = memoryStore.organizations.get(orgId);
    assert.ok(updatedOrg.scheduledReports.lastSentAt);
  });
});
