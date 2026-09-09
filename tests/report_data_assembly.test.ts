import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { memoryStore } from '../src/lib/store';
import { assembleReportData } from '../src/lib/reports/reportData';
import { computeOrgRiskScore } from '../src/lib/risk/orgScore';
import { generateExecutiveSummary } from '../src/lib/ai/analystService';

describe('PDF Report Data Assembly (§1 & §3)', () => {
  const orgId = 'org_report_data_test';

  it('Setup: Seed Organization, Findings, and Assets', async () => {
    memoryStore.organizations.set(orgId, {
      _id: orgId,
      id: orgId,
      name: 'Acme Health Systems',
      slug: 'acme-health',
      plan: 'BUSINESS',
      createdAt: new Date(),
    });

    // Seed 3 findings
    memoryStore.findings.set('f_rep_01', {
      _id: 'f_rep_01',
      organizationId: orgId,
      title: 'Vulnerable Apache HTTP Server (CVE-2021-41773)',
      findingCode: 'CVE-2021-41773',
      severity: 'CRITICAL',
      confidence: 'CONFIRMED',
      status: 'OPEN',
      riskScore: 95,
      assetFqdn: 'ehr.acme-health.com',
      description: 'Path traversal vulnerability in Apache 2.4.49 allows remote code execution.',
      createdAt: new Date(),
    });

    memoryStore.findings.set('f_rep_02', {
      _id: 'f_rep_02',
      organizationId: orgId,
      title: 'Missing Content Security Policy Header',
      findingCode: 'SEC-HEADER-CSP-MISSING',
      severity: 'MEDIUM',
      confidence: 'CONFIRMED',
      status: 'OPEN',
      riskScore: 35,
      assetFqdn: 'portal.acme-health.com',
      description: 'Content-Security-Policy header is not defined.',
      createdAt: new Date(),
    });

    memoryStore.findings.set('f_rep_03', {
      _id: 'f_rep_03',
      organizationId: orgId,
      title: 'Legacy TLS 1.0 Enabled (Resolved)',
      findingCode: 'TLS-LEGACY-VERSION',
      severity: 'LOW',
      confidence: 'CONFIRMED',
      status: 'RESOLVED',
      riskScore: 20,
      assetFqdn: 'legacy.acme-health.com',
      createdAt: new Date(),
    });

    // Seed Assets
    memoryStore.assets.set('a_rep_01', {
      _id: 'a_rep_01',
      organizationId: orgId,
      fqdn: 'ehr.acme-health.com',
      rootDomain: 'acme-health.com',
      type: 'SUBDOMAIN',
      verificationStatus: 'VERIFIED',
    });

    // Seed Risk Score Snapshot
    memoryStore.riskScoreSnapshots.push({
      organizationId: orgId,
      score: 85,
      grade: 'D',
      computedAt: new Date(Date.now() - 86400000),
    });
  });

  it('Field Parity (§1): assembleReportData matches live dashboard source-of-truth exactly', async () => {
    const reportData = await assembleReportData(orgId);
    const liveScore = await computeOrgRiskScore(orgId);
    const liveSummary = await generateExecutiveSummary(orgId);

    // Exact score & grade matching
    assert.strictEqual(reportData.riskScore.score, liveScore.score);
    assert.strictEqual(reportData.riskScore.securityPosture, liveScore.securityPosture);
    assert.strictEqual(reportData.riskScore.grade, liveScore.grade);
    assert.strictEqual(reportData.riskScore.factors.criticalCount, liveScore.factors.criticalCount);
    assert.strictEqual(reportData.riskScore.factors.mediumCount, liveScore.factors.mediumCount);

    // AI Summary text matching verbatim
    assert.strictEqual(reportData.executiveSummary.summaryText, liveSummary.executiveSummary);
    assert.strictEqual(reportData.executiveSummary.totalConfirmedFindings, liveSummary.totalConfirmedFindings);

    // Top open findings matching (highest risk first)
    assert.strictEqual(reportData.topFindings.length, 2); // 2 OPEN findings
    assert.strictEqual(reportData.topFindings[0].findingCode, 'CVE-2021-41773');
    assert.strictEqual(reportData.topFindings[0].riskScore, 95);
    assert.strictEqual(reportData.topFindings[0].severity, 'CRITICAL');
    assert.strictEqual(reportData.topFindings[1].findingCode, 'SEC-HEADER-CSP-MISSING');

    // Scope matching
    assert.strictEqual(reportData.scope.totalAssets, 1);
    assert.strictEqual(reportData.scope.assets[0].fqdn, 'ehr.acme-health.com');

    // Prominent date & reporting period
    assert.ok(reportData.metadata.reportingPeriod.startsWith('As of '));
    assert.ok(reportData.metadata.reportDateFormatted);
  });

  it('Default Branding (§3): Employs PLIŌRA branding and attribution by default', async () => {
    const reportData = await assembleReportData(orgId);

    assert.strictEqual(reportData.branding.isWhiteLabel, false);
    assert.strictEqual(reportData.branding.brandName, 'PLIŌRA Threat Monitor');
    assert.ok(reportData.branding.footerText.includes('PLIŌRA Threat Monitor'));
  });

  it('White-Label Branding (§3): Renders custom agency name and hides PLIŌRA attribution when configured', async () => {
    const whiteLabelOrgId = 'org_whitelabel_test';
    memoryStore.organizations.set(whiteLabelOrgId, {
      _id: whiteLabelOrgId,
      id: whiteLabelOrgId,
      name: 'Alpha Bank NA',
      slug: 'alpha-bank',
      plan: 'PRO',
      reportBranding: {
        whiteLabelEnabled: true,
        customName: 'CyberShield Managed Security',
        customLogo: 'https://cybershield.example.com/logo.png',
      },
      createdAt: new Date(),
    });

    const reportData = await assembleReportData(whiteLabelOrgId);

    assert.strictEqual(reportData.branding.isWhiteLabel, true);
    assert.strictEqual(reportData.branding.brandName, 'CyberShield Managed Security');
    assert.strictEqual(reportData.branding.customLogo, 'https://cybershield.example.com/logo.png');
    assert.ok(reportData.branding.footerText.includes('Alpha Bank NA'));
    assert.ok(!reportData.branding.footerText.includes('PLIŌRA'));
  });
});
