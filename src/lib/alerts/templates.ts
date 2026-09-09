import { AlertType, AlertSeverity } from '@/types';

export interface AlertTemplatePayload {
  type: AlertType;
  severity: AlertSeverity;
  targetName: string; // FQDN or asset name
  findingTitle?: string;
  riskScore?: number;
  reason?: string;
  remediationSummary?: string;
  targetUrl: string;
}

export interface RenderedEmail {
  subject: string;
  headline: string;
  businessImpact: string;
  actionRequired: string;
  html: string;
  text: string;
}

/**
 * Renders plain-language, jargon-free email notifications for SMB owners and admins (§3).
 * Invariant: Never contains raw, sensitive technical evidence dumps.
 */
export function renderAlertEmail(payload: AlertTemplatePayload): RenderedEmail {
  let subject = '';
  let headline = '';
  let businessImpact = '';
  let actionRequired = '';

  switch (payload.type) {
    case 'NEW_CRITICAL_FINDING':
      subject = `[CRITICAL SECURITY ALERT] Immediate Action Required for ${payload.targetName}`;
      headline = `Critical Security Vulnerability Detected on ${payload.targetName}`;
      businessImpact =
        'This issue exposes your system to high risk of external compromise or data interception by attackers.';
      actionRequired =
        payload.remediationSummary ||
        'Review the remediation steps in your security dashboard immediately to close this exposure.';
      break;

    case 'NEW_HIGH_FINDING':
      subject = `[HIGH PRIORITY] Security Exposure Found on ${payload.targetName}`;
      headline = `High-Priority Security Finding on ${payload.targetName}`;
      businessImpact =
        'A significant security misconfiguration was detected that weakens your defenses against automated internet threats.';
      actionRequired =
        payload.remediationSummary ||
        'Check the recommended configuration changes in your dashboard to secure this asset.';
      break;

    case 'FINDING_AUTO_REOPENED':
      subject = `[RE-DETECTED] Previously Resolved Issue Reappeared on ${payload.targetName}`;
      headline = `A previously resolved security issue has resurfaced on ${payload.targetName}`;
      businessImpact =
        'A problem previously marked resolved is active again, indicating a potential configuration rollback or recurrence.';
      actionRequired =
        'Inspect your recent deployment or DNS updates to verify why this configuration regressed.';
      break;

    case 'NEW_ASSET_DISCOVERED':
      subject = `[NEW ASSET] New Subdomain Discovered: ${payload.targetName}`;
      headline = `PLIŌRA discovered a new public endpoint for your domain: ${payload.targetName}`;
      businessImpact =
        'Newly exposed subdomains or certificates increase your attack surface if left unmonitored or unpatched.';
      actionRequired =
        'Verify if this asset is legitimate and review its initial security posture in your dashboard.';
      break;

    case 'SCAN_FAILED':
      subject = `[OPERATIONAL NOTICE] Security Scan Failed for ${payload.targetName}`;
      headline = `Scheduled Security Assessment Could Not Complete on ${payload.targetName}`;
      businessImpact =
        'Target unreachable, DNS resolution failed, or connection timed out during scanning.';
      actionRequired =
        'Check that your domain DNS records are active and responsive, then retry the assessment.';
      break;

    case 'THREAT_DETECTED':
      subject = `[BRAND THREAT ALERT] Look-alike Domain Detected for ${payload.targetName}`;
      headline = `Suspicious Look-alike Domain Targeting Your Brand: ${payload.targetName}`;
      businessImpact =
        'An impersonating or typosquatted domain was registered or configured targeting your verified brand identity. Threat actors frequently weaponize these domains for credential harvesting, executive phishing, or brand hijacking.';
      actionRequired =
        'Review the threat indicators in your dashboard. If unowned, consider filing a registrar abuse notice or submitting a trademark takedown request.';
      break;

    default:
      subject = `[SECURITY NOTICE] Security Alert for ${payload.targetName}`;
      headline = `Security Event Detected on ${payload.targetName}`;
      businessImpact = 'An anomalous configuration or security change was observed.';
      actionRequired = 'Log in to your security dashboard to inspect this event.';
      break;
  }

  const text = `
PLIŌRA Threat Monitor
=====================

${headline}

Target: ${payload.targetName}
Severity: ${payload.severity}${payload.riskScore !== undefined ? ` (Risk Score: ${payload.riskScore}/100)` : ''}

Why this matters to your business:
${businessImpact}

Recommended Action:
${actionRequired}

View details securely in your dashboard:
${payload.targetUrl}

--
PLIŌRA Threat Monitor • Automated Security Intelligence
`.trim();

  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>${subject}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #1e293b; background-color: #f8fafc; margin: 0; padding: 20px; }
    .container { max-width: 580px; margin: 0 auto; background: #ffffff; border-radius: 8px; border: 1px solid #e2e8f0; padding: 32px; }
    .badge { display: inline-block; padding: 4px 10px; font-size: 12px; font-weight: 700; border-radius: 4px; text-transform: uppercase; margin-bottom: 16px; }
    .badge-critical { background: #fee2e2; color: #991b1b; }
    .badge-high { background: #ffedd5; color: #9a3412; }
    .badge-info { background: #e0f2fe; color: #075985; }
    h1 { font-size: 20px; font-weight: 700; color: #0f172a; margin-top: 0; margin-bottom: 16px; }
    .card { background: #f1f5f9; border-left: 4px solid #3b82f6; padding: 16px; margin: 20px 0; border-radius: 0 4px 4px 0; }
    .card-title { font-weight: 600; font-size: 14px; color: #334155; text-transform: uppercase; margin-bottom: 6px; }
    .btn { display: inline-block; background-color: #0f172a; color: #ffffff !important; padding: 12px 24px; font-weight: 600; text-decoration: none; border-radius: 6px; margin-top: 20px; }
    .footer { font-size: 12px; color: #64748b; margin-top: 32px; border-top: 1px solid #e2e8f0; padding-top: 16px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="badge ${payload.severity === 'CRITICAL' ? 'badge-critical' : payload.severity === 'HIGH' ? 'badge-high' : 'badge-info'}">
      ${payload.severity} ALERT
    </div>
    <h1>${headline}</h1>
    <p><strong>Target Endpoint:</strong> <code>${payload.targetName}</code></p>
    ${payload.riskScore !== undefined ? `<p><strong>Calculated Risk Score:</strong> ${payload.riskScore}/100</p>` : ''}
    
    <div class="card">
      <div class="card-title">Why This Matters</div>
      <p style="margin: 0;">${businessImpact}</p>
    </div>

    <div class="card" style="border-left-color: #10b981;">
      <div class="card-title">Recommended Action</div>
      <p style="margin: 0;">${actionRequired}</p>
    </div>

    <div style="text-align: center;">
      <a href="${payload.targetUrl}" class="btn" target="_blank">Open Security Dashboard</a>
    </div>

    <div class="footer">
      <p>This automated security alert was delivered by <strong>PLIŌRA Threat Monitor</strong>. Sensitive technical telemetry is withheld from email and only accessible through your authenticated dashboard.</p>
    </div>
  </div>
</body>
</html>
`.trim();

  return {
    subject,
    headline,
    businessImpact,
    actionRequired,
    html,
    text,
  };
}
