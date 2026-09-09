import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { NextRequest } from 'next/server';
import { memoryStore } from '../src/lib/store';
import { createSessionToken } from '../src/lib/auth';
import { POST as postAgencyInvite } from '../src/app/api/agency/invites/route';
import { GET as getAgencyClients } from '../src/app/api/agency/clients/route';
import { POST as postAgencyRevoke } from '../src/app/api/agency/clients/[id]/revoke/route';
import { GET as getClientLinks } from '../src/app/api/org/agency-links/route';
import { POST as postClientAccept } from '../src/app/api/org/agency-links/[id]/accept/route';
import { POST as postClientRevoke } from '../src/app/api/org/agency-links/[id]/revoke/route';
import { PATCH as patchClientBranding } from '../src/app/api/org/agency-links/[id]/branding/route';
import { GET as getFindings } from '../src/app/api/findings/route';
import { PATCH as patchFinding } from '../src/app/api/findings/[id]/route';
import { POST as postAsset } from '../src/app/api/assets/route';
import { assembleReportData } from '../src/lib/reports/reportData';

describe('Roadmap §D.2: Channel Partnerships / MSP & Agency Resale', () => {
  // Test Organization & User Identifiers
  const agencyOrgId = 'org-msp-sentinel-01';
  const clientAOrgId = 'org-client-alpha-01';
  const clientBOrgId = 'org-client-beta-02';
  const clientFreeOrgId = 'org-client-free-03';

  const agencyAdminUserId = 'user-agency-admin-01';
  const clientAOwnerUserId = 'user-client-a-owner-01';
  const clientAMemberUserId = 'user-client-a-member-01';
  const standardClientUserId = 'user-standard-client-01';

  let agencyAdminCookie: string;
  let clientAOwnerCookie: string;
  let clientAMemberCookie: string;
  let standardClientCookie: string;

  before(() => {
    // Seed Agency Org
    memoryStore.organizations.set(agencyOrgId, {
      _id: agencyOrgId,
      id: agencyOrgId,
      name: 'Sentinel MSP Partners',
      slug: 'sentinel-msp',
      accountType: 'AGENCY',
      plan: 'PRO',
      reportBranding: {
        whiteLabelEnabled: true,
        customName: 'Sentinel Managed Cyber Defense',
        customLogo: 'https://sentinel.msp/logo.png',
      },
    });

    // Seed Client A Org (Business Plan)
    memoryStore.organizations.set(clientAOrgId, {
      _id: clientAOrgId,
      id: clientAOrgId,
      name: 'Alpha Retailers Inc',
      slug: 'alpha-retail',
      accountType: 'STANDARD',
      plan: 'BUSINESS',
      stripeCustomerId: 'cus_alpha_12345',
      stripeSubscriptionId: 'sub_alpha_67890',
      subscriptionStatus: 'ACTIVE',
      reportBranding: {
        whiteLabelEnabled: false,
      },
    });

    // Seed Client B Org (Starter Plan, Unlinked)
    memoryStore.organizations.set(clientBOrgId, {
      _id: clientBOrgId,
      id: clientBOrgId,
      name: 'Beta Logistics Corp',
      slug: 'beta-logistics',
      accountType: 'STANDARD',
      plan: 'STARTER',
      stripeCustomerId: 'cus_beta_12345',
      subscriptionStatus: 'ACTIVE',
    });

    // Seed Client Free Org (Free Plan, Unlinked)
    memoryStore.organizations.set(clientFreeOrgId, {
      _id: clientFreeOrgId,
      id: clientFreeOrgId,
      name: 'Free Starter Co',
      slug: 'free-starter',
      accountType: 'STANDARD',
      plan: 'FREE',
    });

    // Seed Users
    memoryStore.users.set(agencyAdminUserId, {
      _id: agencyAdminUserId,
      id: agencyAdminUserId,
      name: 'Sentinel Security Lead',
      email: 'lead@sentinel.msp',
      role: 'ADMIN',
      organizationMemberships: [{ organizationId: agencyOrgId, role: 'ADMIN' }],
      activeOrganizationId: agencyOrgId,
    });

    memoryStore.users.set(clientAOwnerUserId, {
      _id: clientAOwnerUserId,
      id: clientAOwnerUserId,
      name: 'Alpha Security Director',
      email: 'director@alpharetail.test',
      role: 'OWNER',
      organizationMemberships: [{ organizationId: clientAOrgId, role: 'OWNER' }],
      activeOrganizationId: clientAOrgId,
    });

    memoryStore.users.set(clientAMemberUserId, {
      _id: clientAMemberUserId,
      id: clientAMemberUserId,
      name: 'Alpha Staff Engineer',
      email: 'engineer@alpharetail.test',
      role: 'MEMBER',
      organizationMemberships: [{ organizationId: clientAOrgId, role: 'MEMBER' }],
      activeOrganizationId: clientAOrgId,
    });

    memoryStore.users.set(standardClientUserId, {
      _id: standardClientUserId,
      id: standardClientUserId,
      name: 'Beta Lead Admin',
      email: 'admin@betalogistics.test',
      role: 'OWNER',
      organizationMemberships: [{ organizationId: clientBOrgId, role: 'OWNER' }],
      activeOrganizationId: clientBOrgId,
    });

    // Seed Findings for Client A
    memoryStore.findings.set('finding-alpha-01', {
      _id: 'finding-alpha-01',
      id: 'finding-alpha-01',
      organizationId: clientAOrgId,
      findingCode: 'TLS-EXPIRED-CERT',
      title: 'Expired TLS Handshake Certificate',
      severity: 'CRITICAL',
      confidence: 'CONFIRMED',
      status: 'OPEN',
      riskScore: 90,
      createdAt: new Date(),
    });

    memoryStore.findings.set('finding-alpha-02', {
      _id: 'finding-alpha-02',
      id: 'finding-alpha-02',
      organizationId: clientAOrgId,
      findingCode: 'SEC-HEADER-CSP-MISSING',
      title: 'Content Security Policy Missing',
      severity: 'HIGH',
      confidence: 'CONFIRMED',
      status: 'OPEN',
      riskScore: 65,
      createdAt: new Date(),
    });

    // Seed Finding for Client B (to test isolation)
    memoryStore.findings.set('finding-beta-secret-01', {
      _id: 'finding-beta-secret-01',
      id: 'finding-beta-secret-01',
      organizationId: clientBOrgId,
      findingCode: 'SENSITIVE-ENV-EXPOSED',
      title: 'Beta Secret Production File Exposed',
      severity: 'CRITICAL',
      confidence: 'CONFIRMED',
      status: 'OPEN',
      riskScore: 100,
      createdAt: new Date(),
    });

    // Create session JWT tokens
    agencyAdminCookie = createSessionToken({
      userId: agencyAdminUserId,
      email: 'lead@sentinel.msp',
      organizationId: agencyOrgId,
      role: 'ADMIN',
    });

    clientAOwnerCookie = createSessionToken({
      userId: clientAOwnerUserId,
      email: 'director@alpharetail.test',
      organizationId: clientAOrgId,
      role: 'OWNER',
    });

    clientAMemberCookie = createSessionToken({
      userId: clientAMemberUserId,
      email: 'engineer@alpharetail.test',
      organizationId: clientAOrgId,
      role: 'MEMBER',
    });

    standardClientCookie = createSessionToken({
      userId: standardClientUserId,
      email: 'admin@betalogistics.test',
      organizationId: clientBOrgId,
      role: 'OWNER',
    });
  });

  let createdLinkId: string = '';

  describe('1. Agency-Client Link Lifecycle & Approval Gates (§1)', () => {
    it('Non-agency organization is forbidden from issuing client invitations', async () => {
      const req = new NextRequest('http://localhost:3000/api/agency/invites', {
        method: 'POST',
        headers: {
          cookie: `pliora_session=${clientAOwnerCookie}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ clientOrgSlugOrId: 'beta-logistics' }),
      });

      const res = await postAgencyInvite(req);
      assert.equal(res.status, 403);
      const data = await res.json();
      assert.equal(data.error?.code, 'FORBIDDEN');
    });

    it('Agency issues link invitation -> Status becomes PENDING (not ACTIVE)', async () => {
      const req = new NextRequest('http://localhost:3000/api/agency/invites', {
        method: 'POST',
        headers: {
          cookie: `pliora_session=${agencyAdminCookie}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          clientOrgSlugOrId: 'alpha-retail',
          delegateBranding: true,
        }),
      });

      const res = await postAgencyInvite(req);
      assert.equal(res.status, 201);
      const data = await res.json();
      assert.equal(data.success, true);
      assert.equal(data.data.status, 'PENDING');
      assert.equal(data.data.scopes[0], 'READ_ONLY');
      assert.equal(data.data.delegateBranding, true);

      createdLinkId = data.data.linkId;
      assert.ok(createdLinkId);
    });

    it('While PENDING, agency attempting cross-org access is strictly blocked (403)', async () => {
      const req = new NextRequest('http://localhost:3000/api/findings', {
        method: 'GET',
        headers: {
          cookie: `pliora_session=${agencyAdminCookie}`,
          'x-client-org-id': clientAOrgId,
        },
      });

      const res = await getFindings(req);
      assert.equal(res.status, 403);
      const data = await res.json();
      assert.match(data.error?.message, /No active agency link/i);
    });

    it('Client non-admin (MEMBER) cannot accept agency link invitation (403)', async () => {
      const req = new NextRequest(`http://localhost:3000/api/org/agency-links/${createdLinkId}/accept`, {
        method: 'POST',
        headers: {
          cookie: `pliora_session=${clientAMemberCookie}`,
        },
      });

      const res = await postClientAccept(req, { params: Promise.resolve({ id: createdLinkId }) });
      assert.equal(res.status, 403);
      const data = await res.json();
      assert.equal(data.error?.code, 'INSUFFICIENT_PERMISSIONS');
    });

    it('Client OWNER explicitly accepts link -> Status transitions to ACTIVE', async () => {
      const req = new NextRequest(`http://localhost:3000/api/org/agency-links/${createdLinkId}/accept`, {
        method: 'POST',
        headers: {
          cookie: `pliora_session=${clientAOwnerCookie}`,
        },
      });

      const res = await postClientAccept(req, { params: Promise.resolve({ id: createdLinkId }) });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.success, true);
      assert.equal(data.data.status, 'ACTIVE');
      assert.equal(data.data.grantedByUserId, clientAOwnerUserId);
    });

    it('Now ACTIVE: Agency can read Client A findings via x-client-org-id', async () => {
      const req = new NextRequest('http://localhost:3000/api/findings', {
        method: 'GET',
        headers: {
          cookie: `pliora_session=${agencyAdminCookie}`,
          'x-client-org-id': clientAOrgId,
        },
      });

      const res = await getFindings(req);
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.success, true);
      assert.equal(data.data.length, 2);
      assert.ok(data.data.some((f: any) => f.findingCode === 'TLS-EXPIRED-CERT'));
    });
  });

  describe('2. Immediate Unilateral Revocation by Either Party (§1 & §3)', () => {
    it('Client OWNER revokes agency link -> Takes effect immediately', async () => {
      const req = new NextRequest(`http://localhost:3000/api/org/agency-links/${createdLinkId}/revoke`, {
        method: 'POST',
        headers: {
          cookie: `pliora_session=${clientAOwnerCookie}`,
        },
      });

      const res = await postClientRevoke(req, { params: Promise.resolve({ id: createdLinkId }) });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.success, true);
      assert.equal(data.data.status, 'REVOKED');
    });

    it('Immediate effect verified: Subsequent agency request to Client A fails with 403', async () => {
      const req = new NextRequest('http://localhost:3000/api/findings', {
        method: 'GET',
        headers: {
          cookie: `pliora_session=${agencyAdminCookie}`,
          'x-client-org-id': clientAOrgId,
        },
      });

      const res = await getFindings(req);
      assert.equal(res.status, 403);
      const data = await res.json();
      assert.match(data.error?.message, /No active agency link/i);
    });

    it('Re-activating and testing Agency-side immediate revocation', async () => {
      // Re-activate link
      const link = memoryStore.agencyClientLinks.get(createdLinkId);
      link.status = 'ACTIVE';
      memoryStore.agencyClientLinks.set(createdLinkId, link);

      // Agency revokes link
      const req = new NextRequest(`http://localhost:3000/api/agency/clients/${createdLinkId}/revoke`, {
        method: 'POST',
        headers: {
          cookie: `pliora_session=${agencyAdminCookie}`,
        },
      });

      const res = await postAgencyRevoke(req, { params: Promise.resolve({ id: createdLinkId }) });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.success, true);
      assert.equal(data.data.status, 'REVOKED');

      // Subsequent access rejected
      const accessReq = new NextRequest('http://localhost:3000/api/findings', {
        method: 'GET',
        headers: {
          cookie: `pliora_session=${agencyAdminCookie}`,
          'x-client-org-id': clientAOrgId,
        },
      });
      const accessRes = await getFindings(accessReq);
      assert.equal(accessRes.status, 403);

      // Reset to ACTIVE for subsequent tests
      link.status = 'ACTIVE';
      memoryStore.agencyClientLinks.set(createdLinkId, link);
    });
  });

  describe('3. Cross-Tenant Isolation Boundary Rigor (§6)', () => {
    it('Agency with ACTIVE link to Client A is 100% blocked from Client B (403)', async () => {
      const req = new NextRequest('http://localhost:3000/api/findings', {
        method: 'GET',
        headers: {
          cookie: `pliora_session=${agencyAdminCookie}`,
          'x-client-org-id': clientBOrgId,
        },
      });

      const res = await getFindings(req);
      assert.equal(res.status, 403);
      const data = await res.json();
      assert.match(data.error?.message, /No active agency link/i);
    });

    it('Standard non-agency organization cannot use x-client-org-id delegation (403)', async () => {
      const req = new NextRequest('http://localhost:3000/api/findings', {
        method: 'GET',
        headers: {
          cookie: `pliora_session=${standardClientCookie}`,
          'x-client-org-id': clientAOrgId,
        },
      });

      const res = await getFindings(req);
      assert.equal(res.status, 403);
      const data = await res.json();
      assert.match(data.error?.message, /Only agency accounts/i);
    });
  });

  describe('4. Server-Side Read-Only Scoping Enforcement (§1 & §6)', () => {
    it('Agency user delegating into Client A cannot add assets (POST /api/assets rejected with 403)', async () => {
      const req = new NextRequest('http://localhost:3000/api/assets', {
        method: 'POST',
        headers: {
          cookie: `pliora_session=${agencyAdminCookie}`,
          'x-client-org-id': clientAOrgId,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          domain: 'unauthorized-asset.alpharetail.test',
        }),
      });

      const res = await postAsset(req);
      assert.equal(res.status, 403);
      const data = await res.json();
      assert.equal(data.error?.code, 'INSUFFICIENT_PERMISSIONS');
    });

    it('Agency user delegating into Client A cannot triage or resolve findings (PATCH rejected with 403)', async () => {
      const req = new NextRequest('http://localhost:3000/api/findings/finding-alpha-01', {
        method: 'PATCH',
        headers: {
          cookie: `pliora_session=${agencyAdminCookie}`,
          'x-client-org-id': clientAOrgId,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          status: 'RESOLVED',
          notes: 'Agency attempted resolution on behalf of client',
        }),
      });

      const res = await patchFinding(req, { params: Promise.resolve({ id: 'finding-alpha-01' }) });
      assert.equal(res.status, 403);
      const data = await res.json();
      assert.equal(data.error?.code, 'INSUFFICIENT_PERMISSIONS');
    });
  });

  describe('5. Dual Audit Logging (§2 & §6)', () => {
    it('Cross-org access logs to BOTH Client audit trail and Agency audit trail', async () => {
      // Clear audit log buffer for clarity
      memoryStore.auditLogs = [];

      const req = new NextRequest('http://localhost:3000/api/findings', {
        method: 'GET',
        headers: {
          cookie: `pliora_session=${agencyAdminCookie}`,
          'x-client-org-id': clientAOrgId,
        },
      });

      const res = await getFindings(req);
      assert.equal(res.status, 200);

      // Verify client organization audit trail has AGENCY_DATA_ACCESSED
      const clientLogs = memoryStore.auditLogs.filter(
        (l) => l.organizationId === clientAOrgId && l.action === 'AGENCY_DATA_ACCESSED'
      );
      assert.equal(clientLogs.length, 1);
      assert.equal(clientLogs[0].actorId, 'lead@sentinel.msp');
      assert.equal(clientLogs[0].details?.agencyName, 'Sentinel MSP Partners');
      assert.equal(clientLogs[0].details?.path, '/api/findings');

      // Verify agency organization audit trail has AGENCY_CLIENT_ACCESSED
      const agencyLogs = memoryStore.auditLogs.filter(
        (l) => l.organizationId === agencyOrgId && l.action === 'AGENCY_CLIENT_ACCESSED'
      );
      assert.equal(agencyLogs.length, 1);
      assert.equal(agencyLogs[0].details?.clientName, 'Alpha Retailers Inc');
    });

    it('Client settings endpoint surfaces agency access logs', async () => {
      const req = new NextRequest('http://localhost:3000/api/org/agency-links', {
        method: 'GET',
        headers: {
          cookie: `pliora_session=${clientAOwnerCookie}`,
        },
      });

      const res = await getClientLinks(req);
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.success, true);
      assert.ok(data.data.accessLogs.length >= 1);
      assert.equal(data.data.accessLogs[0].agencyName, 'Sentinel MSP Partners');
    });
  });

  describe('6. White-Label Report Branding Precedence (§4)', () => {
    it('Tier gating: FREE tier client with agency link CANNOT bypass plan tier (standard branding)', async () => {
      // Create active link to Free Org
      memoryStore.agencyClientLinks.set('link-free-01', {
        _id: 'link-free-01',
        agencyOrgId: agencyOrgId,
        clientOrgId: clientFreeOrgId,
        status: 'ACTIVE',
        delegateBranding: true,
      });

      const reportData = await assembleReportData(clientFreeOrgId, {
        agencyOrgId: agencyOrgId,
      });

      assert.equal(reportData.branding.isWhiteLabel, false);
      assert.equal(reportData.branding.brandName, 'PLIŌRA Threat Monitor');
    });

    it('Precedence Rule A: BUSINESS tier client with delegateBranding: true receives Agency branding', async () => {
      const link = memoryStore.agencyClientLinks.get(createdLinkId);
      link.delegateBranding = true;
      memoryStore.agencyClientLinks.set(createdLinkId, link);

      const reportData = await assembleReportData(clientAOrgId, {
        agencyOrgId: agencyOrgId,
      });

      assert.equal(reportData.branding.isWhiteLabel, true);
      assert.equal(reportData.branding.brandName, 'Sentinel Managed Cyber Defense');
      assert.equal(reportData.branding.customLogo, 'https://sentinel.msp/logo.png');
      assert.match(reportData.branding.footerText, /Report prepared for Alpha Retailers Inc by Sentinel Managed Cyber Defense/);
    });

    it('Precedence Rule B: Client with custom branding overrides agency default when delegateBranding: false', async () => {
      const link = memoryStore.agencyClientLinks.get(createdLinkId);
      link.delegateBranding = false;
      memoryStore.agencyClientLinks.set(createdLinkId, link);

      // Client configures custom branding
      const clientOrg = memoryStore.organizations.get(clientAOrgId);
      clientOrg.reportBranding = {
        whiteLabelEnabled: true,
        customName: 'Alpha Secure Operations',
        customLogo: 'https://alpharetail.test/logo.png',
      };
      memoryStore.organizations.set(clientAOrgId, clientOrg);

      const reportData = await assembleReportData(clientAOrgId, {
        agencyOrgId: agencyOrgId,
      });

      assert.equal(reportData.branding.isWhiteLabel, true);
      assert.equal(reportData.branding.brandName, 'Alpha Secure Operations');
      assert.equal(reportData.branding.customLogo, 'https://alpharetail.test/logo.png');
    });

    it('Precedence Rule C: When client unconfigured and delegateBranding: false, falls back to agency default', async () => {
      // Client removes custom branding
      const clientOrg = memoryStore.organizations.get(clientAOrgId);
      clientOrg.reportBranding = {
        whiteLabelEnabled: false,
      };
      memoryStore.organizations.set(clientAOrgId, clientOrg);

      const reportData = await assembleReportData(clientAOrgId, {
        agencyOrgId: agencyOrgId,
      });

      assert.equal(reportData.branding.isWhiteLabel, true);
      assert.equal(reportData.branding.brandName, 'Sentinel Managed Cyber Defense');
    });
  });

  describe('7. Partner Reseller Billing Neutrality (§5)', () => {
    it('Agency links have ZERO side-effects on client Stripe subscription state', async () => {
      const clientOrg = memoryStore.organizations.get(clientAOrgId);
      assert.equal(clientOrg.stripeCustomerId, 'cus_alpha_12345');
      assert.equal(clientOrg.stripeSubscriptionId, 'sub_alpha_67890');
      assert.equal(clientOrg.subscriptionStatus, 'ACTIVE');
      assert.equal(clientOrg.plan, 'BUSINESS');

      // Toggling branding delegation
      const brandingReq = new NextRequest(`http://localhost:3000/api/org/agency-links/${createdLinkId}/branding`, {
        method: 'PATCH',
        headers: {
          cookie: `pliora_session=${clientAOwnerCookie}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ delegateBranding: true }),
      });
      await patchClientBranding(brandingReq, { params: Promise.resolve({ id: createdLinkId }) });

      // Revoking link
      const revokeReq = new NextRequest(`http://localhost:3000/api/org/agency-links/${createdLinkId}/revoke`, {
        method: 'POST',
        headers: {
          cookie: `pliora_session=${clientAOwnerCookie}`,
        },
      });
      await postClientRevoke(revokeReq, { params: Promise.resolve({ id: createdLinkId }) });

      // Verify zero changes to Stripe subscription or plan
      const clientOrgAfter = memoryStore.organizations.get(clientAOrgId);
      assert.equal(clientOrgAfter.stripeCustomerId, 'cus_alpha_12345');
      assert.equal(clientOrgAfter.stripeSubscriptionId, 'sub_alpha_67890');
      assert.equal(clientOrgAfter.subscriptionStatus, 'ACTIVE');
      assert.equal(clientOrgAfter.plan, 'BUSINESS');
    });
  });

  describe('8. Agency Multi-Client Console Portfolio API (§2)', () => {
    it('GET /api/agency/clients returns aggregated client cards with live scores and finding counts', async () => {
      // Re-enable active link
      const link = memoryStore.agencyClientLinks.get(createdLinkId);
      link.status = 'ACTIVE';
      memoryStore.agencyClientLinks.set(createdLinkId, link);

      const req = new NextRequest('http://localhost:3000/api/agency/clients', {
        method: 'GET',
        headers: {
          cookie: `pliora_session=${agencyAdminCookie}`,
        },
      });

      const res = await getAgencyClients(req);
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.success, true);
      assert.equal(data.data.totalActiveClients, 2); // Client A and Client Free

      const clientACard = data.data.clients.find((c: any) => c.clientOrgId === clientAOrgId);
      assert.ok(clientACard);
      assert.equal(clientACard.name, 'Alpha Retailers Inc');
      assert.equal(clientACard.plan, 'BUSINESS');
      assert.ok(typeof clientACard.riskScore === 'number');
      assert.ok(typeof clientACard.securityPosture === 'number');
      assert.ok(['A', 'B', 'C', 'D', 'F'].includes(clientACard.grade));
      assert.equal(clientACard.openCriticalCount, 1);
      assert.equal(clientACard.openHighCount, 1);
    });
  });
});
