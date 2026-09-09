import { REMEDIATION_LIBRARY } from './remediationLibrary';

export function buildFindingExplanationPrompt(finding: any, evidence: any, asset: any) {
  const code = finding.findingCode || 'GENERAL';
  const guidance = REMEDIATION_LIBRARY[code];
  const approvedStepsList = guidance
    ? guidance.approvedSteps.map((s, idx) => `  ${idx + 1}. ${s}`).join('\n')
    : '  1. Review security configuration on target domain.';

  const systemPrompt = `You are PLIŌRA Threat Monitor's Grounded AI Security Analyst.
Your task is to provide a plain-language explanation of a confirmed security finding for an SMB business owner.

NON-NEGOTIABLE GROUNDING RULES:
1. Explain ONLY the technical facts provided in the Input Data JSON.
2. DO NOT hallucinate or invent CVEs, open ports, software versions, or vulnerabilities not present in the Input Data.
3. If confidence is MEDIUM, LOW, or INFORMATIONAL, you MUST hedge: state what was observed, but DO NOT claim the system is actively breached, exploited, or definitely vulnerable.
4. For remediation steps, you MUST select or paraphrase ONLY from the Approved Remediation Steps provided below. Do not create novel steps.
5. In "citedEvidenceFields", list the exact property names from the input JSON that you based your explanation on.`;

  const userPrompt = `Input Data:
${JSON.stringify(
  {
    finding: {
      category: finding.category,
      findingCode: finding.findingCode,
      title: finding.title,
      description: finding.description,
      severity: finding.severity,
      confidence: finding.confidence,
      riskScore: finding.riskScore,
    },
    asset: {
      fqdn: asset?.fqdn,
      type: asset?.type,
      importance: asset?.importance,
    },
    evidence: {
      checkType: evidence?.checkType,
      targetDomain: evidence?.targetDomain,
      details: evidence?.details,
    },
  },
  null,
  2
)}

Approved Remediation Steps for ${code}:
${approvedStepsList}

Return a valid JSON object matching this exact schema:
{
  "explanation": "Clear, plain-language description of the issue for a non-technical owner",
  "businessImpact": "Why this matters to the business, avoiding technical jargon",
  "remediationSteps": ["Selected step from approved list", "Another step from approved list"],
  "citedEvidenceFields": ["field1", "field2"]
}`;

  return { systemPrompt, userPrompt };
}

export function buildThreatExplanationPrompt(threat: any, evidence: any) {
  const code = threat.source === 'TYPOSQUAT_PERMUTATION' ? 'TYPOSQUAT_DOMAIN_DETECTED' : 'BRAND_THREAT';
  const guidance = REMEDIATION_LIBRARY[code] || REMEDIATION_LIBRARY.TYPOSQUAT_DOMAIN_DETECTED;
  const approvedStepsList = guidance.approvedSteps.map((s, idx) => `  ${idx + 1}. ${s}`).join('\n');

  const systemPrompt = `You are PLIŌRA Threat Monitor's Grounded AI Security Analyst.
Your task is to explain a brand protection threat (e.g. typosquat look-alike domain) to an SMB business owner.

NON-NEGOTIABLE GROUNDING RULES:
1. Ground your explanation strictly on the corroboration factors provided in the Input Data.
2. If the domain is non-resolving or has low corroboration, state clearly that it is currently dormant/inactive.
3. If the domain has active mail (MX) or live IPs, explain the risk of email spoofing or credential phishing.
4. Select remediation steps ONLY from the approved steps provided.
5. In "citedEvidenceFields", list the exact property names from the input JSON that support your assessment.`;

  const userPrompt = `Input Data:
${JSON.stringify(
  {
    threat: {
      indicator: threat.indicator,
      relatedRootDomain: threat.relatedRootDomain,
      source: threat.source,
      confidence: threat.confidence,
      corroborationScore: threat.corroborationScore,
      corroborationFactors: threat.corroborationFactors,
      resolvedIps: threat.resolvedIps,
      registrarAge: threat.registrarAge,
      hostingAsn: threat.hostingAsn,
    },
    evidence: evidence?.details || evidence?.rawOutput ? { details: evidence.details } : undefined,
  },
  null,
  2
)}

Approved Remediation Steps:
${approvedStepsList}

Return a valid JSON object matching this exact schema:
{
  "explanation": "Clear, plain-language description of the look-alike threat",
  "businessImpact": "Why this look-alike domain matters to brand security and customer trust",
  "remediationSteps": ["Selected step from approved list", "Another step from approved list"],
  "citedEvidenceFields": ["field1", "field2"]
}`;

  return { systemPrompt, userPrompt };
}

export function buildExecutiveSummaryPrompt(findings: any[], threats: any[], org: any) {
  const systemPrompt = `You are PLIŌRA Threat Monitor's Executive Security Analyst.
Summarize external security posture for company leadership.
CRITICAL CONSTRAINT: You must ONLY reference the high-priority and confirmed findings provided in the Input Data.`;

  const userPrompt = `Organization: ${org.name}
High-Priority Findings (${findings.length}):
${JSON.stringify(findings.slice(0, 10), null, 2)}

High-Priority Threats (${threats.length}):
${JSON.stringify(threats.slice(0, 10), null, 2)}

Return a valid JSON object matching this exact schema:
{
  "executiveSummary": "1-2 paragraphs summarizing executive security posture and key external exposures",
  "overallPosture": "CRITICAL" | "POOR" | "MODERATE" | "GOOD" | "EXCELLENT",
  "keyRisks": [
    {
      "title": "Brief title of risk",
      "severity": "CRITICAL" | "HIGH",
      "affectedAssetOrIndicator": "domain.com",
      "impact": "Plain-language operational impact"
    }
  ],
  "priorityActions": [
    "Most urgent remediation action",
    "Second priority remediation action"
  ]
}`;

  return { systemPrompt, userPrompt };
}
