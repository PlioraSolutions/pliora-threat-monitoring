import { AIExplanationResult, ExecutiveSummaryResult } from './types';
import { getConfidenceCaveat } from './schema';
import { REMEDIATION_LIBRARY } from './remediationLibrary';

export function generateFindingFallback(finding: any, evidence?: any, asset?: any): AIExplanationResult {
  const code = finding.findingCode || 'GENERAL';
  const guidance = REMEDIATION_LIBRARY[code];
  const severity = finding.severity || 'INFORMATIONAL';
  const confidence = finding.confidence || 'INFORMATIONAL';
  const targetHost = asset?.fqdn || evidence?.targetDomain || 'target asset';

  let explanation = `The security scanner detected ${finding.title} on ${targetHost}.`;
  let businessImpact = `This issue can weaken the security posture of ${targetHost}, potentially allowing attackers to gather reconnaissance or compromise client communications.`;

  if (code === 'TLS_WEAK_PROTOCOL') {
    explanation = `The web server at ${targetHost} supports deprecated TLS 1.0 or TLS 1.1 cryptographic protocols.`;
    businessImpact = `Modern browsers flag outdated protocols as insecure. Using legacy encryption exposes customer communications to traffic interception and fails regulatory compliance (such as PCI-DSS).`;
  } else if (code === 'TLS_CERT_EXPIRED') {
    explanation = `The SSL/TLS certificate securing ${targetHost} has expired.`;
    businessImpact = `Visitors will receive prominent browser security warnings blocking access to the website, leading to severe brand damage, lost customer trust, and dropped transactions.`;
  } else if (code === 'MISSING_HSTS_HEADER') {
    explanation = `The web server at ${targetHost} does not enforce HTTP Strict Transport Security (HSTS).`;
    businessImpact = `Without HSTS, user connections can be downgraded to unencrypted HTTP, allowing attackers on shared networks (such as public Wi-Fi) to eavesdrop on sensitive credentials.`;
  } else if (code === 'MISSING_CSP_HEADER') {
    explanation = `No Content Security Policy (CSP) header is configured on ${targetHost}.`;
    businessImpact = `The application lacks defenses against Cross-Site Scripting (XSS) and malicious script injection, increasing the risk of customer session hijacking.`;
  } else if (code === 'SERVER_BANNER_DISCLOSURE') {
    explanation = `The web server at ${targetHost} broadcasts detailed server software and version numbers in HTTP responses.`;
    businessImpact = `Disclosing server versions allows attackers to rapidly identify whether known unpatched vulnerabilities apply to your specific infrastructure.`;
  }

  const steps = guidance?.approvedSteps?.slice(0, 3) || [
    'Review the technical configuration on the affected server.',
    'Apply industry-standard security hardening guidelines.',
  ];

  return {
    explanation,
    businessImpact,
    remediationSteps: steps,
    confidenceCaveat: getConfidenceCaveat(confidence),
    citedEvidenceFields: ['findingCode', 'severity', 'confidence', 'description'],
    isFallback: true,
    isAIGenerated: false,
    generatedAt: new Date().toISOString(),
  };
}

export function generateThreatFallback(threat: any, evidence?: any): AIExplanationResult {
  const indicator = threat.indicator || 'suspicious domain';
  const brand = threat.relatedRootDomain || 'your brand';
  const score = threat.corroborationScore || 0;
  const confidence = threat.confidence || 'INFORMATIONAL';
  const factors = threat.corroborationFactors || {};

  let explanation = `A look-alike domain (${indicator}) closely resembling ${brand} was discovered.`;
  let businessImpact = `Deceptive domains can be used for executive impersonation, phishing attacks against employees or customers, or fraudulent brand confusion.`;

  if (!factors.isResolving) {
    explanation = `A look-alike domain (${indicator}) was generated based on typosquatting patterns. It is currently dormant and not resolving on public DNS.`;
    businessImpact = `While inactive today, the domain could be registered or activated in the future to conduct phishing campaigns.`;
  } else if (factors.hasMxRecords) {
    explanation = `The deceptive domain ${indicator} resolves to active IP infrastructure and has mail (MX) servers configured.`;
    businessImpact = `Active mail servers on a look-alike domain indicate potential weaponization for outbound phishing or spoofing attacks targeting your customers or staff.`;
  }

  const code = factors.hasMxRecords ? 'TYPOSQUAT_ACTIVE_MX' : 'TYPOSQUAT_DOMAIN_DETECTED';
  const guidance = REMEDIATION_LIBRARY[code] || REMEDIATION_LIBRARY.TYPOSQUAT_DOMAIN_DETECTED;

  return {
    explanation,
    businessImpact,
    remediationSteps: guidance.approvedSteps.slice(0, 3),
    confidenceCaveat: getConfidenceCaveat(confidence),
    citedEvidenceFields: ['indicator', 'source', 'confidence', 'corroborationScore'],
    isFallback: true,
    isAIGenerated: false,
    generatedAt: new Date().toISOString(),
  };
}

export function generateExecutiveSummaryFallback(
  findings: any[],
  threats: any[],
  org: any
): ExecutiveSummaryResult {
  const criticalCount = findings.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = findings.filter((f) => f.severity === 'HIGH').length;
  const highThreatCount = threats.filter((t) => ['CONFIRMED', 'HIGH'].includes(t.confidence)).length;

  let overallPosture: 'CRITICAL' | 'POOR' | 'MODERATE' | 'GOOD' | 'EXCELLENT' = 'GOOD';
  if (criticalCount > 0) overallPosture = 'CRITICAL';
  else if (highCount > 2 || highThreatCount > 2) overallPosture = 'POOR';
  else if (highCount > 0 || highThreatCount > 0) overallPosture = 'MODERATE';
  else overallPosture = 'EXCELLENT';

  const executiveSummary =
    overallPosture === 'CRITICAL' || overallPosture === 'POOR'
      ? `${org.name}'s external security posture requires immediate management attention. Active scans identified ${criticalCount} critical exposures and ${highCount} high-severity findings across monitored assets, alongside ${highThreatCount} high-risk look-alike domain threats.`
      : `${org.name}'s external security perimeter remains in relatively healthy condition. No critical exposures were identified across monitored public-facing domains, though ${highCount} configuration improvements and ${highThreatCount} look-alike brand threats should be reviewed.`;

  const keyRisks = [];
  for (const f of findings.slice(0, 5)) {
    keyRisks.push({
      title: f.title,
      severity: f.severity,
      affectedAssetOrIndicator: f.targetDomain || f.assetFqdn || 'Monitored Asset',
      impact: f.description?.slice(0, 150) || 'Potential exposure of service infrastructure.',
    });
  }
  for (const t of threats.slice(0, 3)) {
    keyRisks.push({
      title: `Brand Impersonation Threat: ${t.indicator}`,
      severity: 'HIGH',
      affectedAssetOrIndicator: t.indicator,
      impact: `Look-alike domain matching ${t.relatedRootDomain} with active infrastructure.`,
    });
  }

  const priorityActions = [
    'Remediate any exposed critical transport or certificate configurations immediately.',
    'Deploy essential HTTP security headers (HSTS, CSP) across all public entry points.',
    'Monitor active typosquat look-alike domains and enforce email authentication (DMARC/SPF).',
  ];

  return {
    executiveSummary,
    overallPosture,
    keyRisks,
    priorityActions,
    totalConfirmedFindings: findings.length,
    totalHighThreats: highThreatCount,
    isFallback: true,
    isAIGenerated: false,
    generatedAt: new Date().toISOString(),
  };
}
